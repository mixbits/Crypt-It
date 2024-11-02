from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey
import getpass
import os
from tqdm import tqdm
import argparse
import secrets
import struct

class EncryptionError(Exception):
    pass

def generate_key(password, salt, iterations=600000):
    """Generate encryption key using PBKDF2-HMAC-SHA256 with increased iterations."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def compute_mac(key, ciphertext):
    """Compute HMAC-SHA256 of the ciphertext."""
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    return h.finalize()

def encrypt_file(file_path, output_path, password):
    try:
        # Generate random salt and IV
        salt = os.urandom(16)
        iv = os.urandom(16)
        
        # Generate encryption key and MAC key
        key = generate_key(password, salt)
        mac_key = generate_key(password, salt + b"mac")  # Separate key for MAC
        
        # Setup encryption
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()

        # Write header with version and iterations
        version = 1
        iterations = 600000
        header = struct.pack('<II', version, iterations)
        
        chunk_size = 1024 * 1024  # 1MB chunks
        total_size = os.path.getsize(file_path)
        progress_bar = tqdm(total=total_size, unit='B', unit_scale=True, desc='Encrypting')

        # Initialize HMAC
        all_ciphertext = bytearray()

        with open(file_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            # Write header, salt, and IV
            outfile.write(header)
            outfile.write(salt)
            outfile.write(iv)

            while True:
                chunk = infile.read(chunk_size)
                if not chunk:
                    break
                padded_chunk = padder.update(chunk)
                encrypted_chunk = encryptor.update(padded_chunk)
                all_ciphertext.extend(encrypted_chunk)
                outfile.write(encrypted_chunk)
                progress_bar.update(len(chunk))

            # Finalize encryption
            padded_chunk = padder.finalize()
            encrypted_chunk = encryptor.update(padded_chunk) + encryptor.finalize()
            all_ciphertext.extend(encrypted_chunk)
            outfile.write(encrypted_chunk)

            # Compute and write MAC
            mac = compute_mac(mac_key, bytes(all_ciphertext))
            outfile.write(mac)

        progress_bar.close()
        return True

    except Exception as e:
        raise EncryptionError(f'Encryption failed: {str(e)}')

def decrypt_file(file_path, output_path, password):
    try:
        with open(file_path, 'rb') as infile:
            # Read header
            header = infile.read(8)
            version, iterations = struct.unpack('<II', header)
            
            if version != 1:
                raise ValueError(f"Unsupported version: {version}")
            
            # Read salt, IV, and MAC
            salt = infile.read(16)
            iv = infile.read(16)
            
            # Generate keys
            key = generate_key(password, salt, iterations)
            mac_key = generate_key(password, salt + b"mac", iterations)

            # Read ciphertext and MAC
            ciphertext = infile.read()
            mac = ciphertext[-32:]  # Last 32 bytes are MAC
            ciphertext = ciphertext[:-32]  # Rest is ciphertext

            # Verify MAC
            expected_mac = compute_mac(mac_key, ciphertext)
            if not secrets.compare_digest(mac, expected_mac):
                raise InvalidKey("Message authentication failed")

            # Setup decryption
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(128).unpadder()

            # Decrypt in memory since we've already verified MAC
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

            # Write decrypted data
            with open(output_path, 'wb') as outfile:
                outfile.write(unpadded_data)

        return True

    except InvalidKey:
        if os.path.exists(output_path):
            os.remove(output_path)
        raise EncryptionError("Invalid password or corrupted file")
    except Exception as e:
        if os.path.exists(output_path):
            os.remove(output_path)
        raise EncryptionError(f'Decryption failed: {str(e)}')

def main():
    parser = argparse.ArgumentParser(description='Securely encrypt or decrypt files.')
    parser.add_argument('-e', '--encrypt', help='Encrypt the specified file', action='store_true')
    parser.add_argument('-d', '--decrypt', help='Decrypt the specified .enc file', action='store_true')
    parser.add_argument('file', help='The file to encrypt or decrypt')
    parser.add_argument('-o', '--output', help='Output file path (optional)')
    
    try:
        args = parser.parse_args()

        if not (args.encrypt or args.decrypt):
            parser.error('No action requested, add -e to encrypt or -d to decrypt')

        if args.encrypt and args.decrypt:
            parser.error('Please specify only one action, either -e or -d')

        if not os.path.exists(args.file):
            print(f'File not found: {args.file}')
            return

        # Determine output path
        if args.output:
            output_path = args.output
        else:
            output_path = args.file + '.enc' if args.encrypt else args.file[:-4]

        # Check if output file already exists
        if os.path.exists(output_path):
            response = input(f'Output file {output_path} already exists. Overwrite? (y/N) ').lower()
            if response != 'y':
                print('Operation cancelled')
                return

        # Get password
        if args.encrypt:
            while True:
                password = getpass.getpass('Enter encryption password: ')
                if len(password) < 8:
                    print('Password must be at least 8 characters long')
                    continue
                confirm = getpass.getpass('Confirm encryption password: ')
                if password != confirm:
                    print('Passwords do not match')
                    continue
                break
        else:
            password = getpass.getpass('Enter decryption password: ')

        # Perform encryption/decryption
        try:
            if args.encrypt:
                encrypt_file(args.file, output_path, password)
                print(f'File encrypted and saved to {output_path}')
            else:
                decrypt_file(args.file, output_path, password)
                print(f'File decrypted and saved to {output_path}')
        except EncryptionError as e:
            print(f'Error: {str(e)}')

    except KeyboardInterrupt:
        print('\nOperation cancelled by user')
        if 'output_path' in locals() and os.path.exists(output_path):
            os.remove(output_path)

if __name__ == '__main__':
    main()
