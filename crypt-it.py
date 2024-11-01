from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import getpass
import hashlib
import os
from tqdm import tqdm
import argparse

def generate_key(password, salt):
    # Generate 32 bytes (256 bits) key using PBKDF2
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

def encrypt_file(file_path, output_path, password):
    try:
        # Generate random salt
        salt = os.urandom(16)
        key = generate_key(password, salt)
        # Generate random IV
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()

        chunk_size = 1024 * 1024  # 1MB chunks
        total_size = os.path.getsize(file_path)
        progress_bar = tqdm(total=total_size, unit='B', unit_scale=True, desc='Encrypting')

        with open(file_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            # Write the salt and IV at the beginning of the output file
            outfile.write(salt)
            outfile.write(iv)

            while True:
                chunk = infile.read(chunk_size)
                if len(chunk) == 0:
                    break
                padded_chunk = padder.update(chunk)
                encrypted_chunk = encryptor.update(padded_chunk)
                outfile.write(encrypted_chunk)
                progress_bar.update(len(chunk))

            # Finalize padding and encryption
            padded_chunk = padder.finalize()
            encrypted_chunk = encryptor.update(padded_chunk) + encryptor.finalize()
            outfile.write(encrypted_chunk)
        progress_bar.close()
    except Exception as e:
        print(f'An error occurred during encryption: {e}')

def decrypt_file(file_path, output_path, password):
    try:
        with open(file_path, 'rb') as infile:
            # Read salt and IV from the beginning of the file
            salt = infile.read(16)
            iv = infile.read(16)
            key = generate_key(password, salt)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(128).unpadder()

            chunk_size = 1024 * 1024  # 1MB chunks
            total_size = os.path.getsize(file_path) - 32  # Adjust for salt and IV
            progress_bar = tqdm(total=total_size, unit='B', unit_scale=True, desc='Decrypting')

            with open(output_path, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    decrypted_chunk = decryptor.update(chunk)
                    data = unpadder.update(decrypted_chunk)
                    outfile.write(data)
                    progress_bar.update(len(chunk))

                # Finalize decryption and unpadding
                decrypted_chunk = decryptor.finalize()
                try:
                    data = unpadder.update(decrypted_chunk)
                    data += unpadder.finalize()
                    outfile.write(data)
                except ValueError:
                    print("Incorrect decryption password or corrupted file.")
                    progress_bar.close()
                    os.remove(output_path)  # Remove incomplete file
                    return
            progress_bar.close()
    except Exception as e:
        print(f'An error occurred during decryption: {e}')

def main():
    try:
        parser = argparse.ArgumentParser(description='Encrypt or decrypt files.')
        parser.add_argument('-e', '--encrypt', help='Encrypt the specified file.', action='store_true')
        parser.add_argument('-d', '--decrypt', help='Decrypt the specified .enc file.', action='store_true')
        parser.add_argument('file', help='The file to encrypt or decrypt.')
        args = parser.parse_args()

        if not (args.encrypt or args.decrypt):
            parser.error('No action requested, add -e to encrypt or -d to decrypt.')

        if args.encrypt and args.decrypt:
            parser.error('Please specify only one action, either -e or -d.')

        file_path = args.file

        if not os.path.exists(file_path):
            print(f'File not found: {file_path}')
            return

        if args.encrypt:
            # Encryption
            password = getpass.getpass('Enter encryption password: ')
            confirm_password = getpass.getpass('Confirm encryption password: ')
            if password != confirm_password:
                print("Passwords do not match.")
                return
            output_path = file_path + '.enc'
            encrypt_file(file_path, output_path, password)
            print(f'File encrypted and saved to {output_path}')

        elif args.decrypt:
            # Decryption
            password = getpass.getpass('Enter decryption password: ')
            if not file_path.endswith('.enc'):
                print('Please provide a .enc file for decryption.')
                return
            output_path = file_path[:-4]
            decrypt_file(file_path, output_path, password)
            print(f'File decrypted and saved to {output_path}')
    except KeyboardInterrupt:
        print('\nOperation cancelled by user.')

if __name__ == '__main__':
    main()
