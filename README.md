# Crypt-It
================

A Simple AES-CBC Encryption Tool for Files

### Table of Contents

* [Installation](#installation)
* [Usage](#usage)
	+ [Encryption](#encryption)
	+ [Decryption](#decryption)
* [Requirements](#requirements)

## Installation

To install Crypt-It, run the following command in your terminal:

```bash
pip install -r requirements.txt

This will install all necessary dependencies for running the program.

##Usage
Encryption
To encrypt a file using Crypt-It, simply run the following command:

python crypt_it.py -e <input_file>

Replace <input_file> with the path to the file you want to encrypt. You will be prompted to enter an encryption password and confirm it.

Example:

$ python crypt_it.py -e [yourfile].doc
Enter encryption password: [yourpassword]
Confirm encryption password: [yourpassword]

File encrypted and saved to example.txt.enc

The original file (example.txt) will be replaced with the encrypted version (example.txt.enc).

Decryption
To decrypt a file, run the following command:

python crypt_it.py -d <input_file>

Replace <input_file> with the path to the .enc file you want to decrypt. You will be prompted to enter the decryption password.

Example:

$ python crypt_it.py -d example.txt.enc
Enter decryption password:[yourpassword]

File decrypted and saved to example.txt

The original encrypted file (example.txt.enc) will be replaced with the decrypted version (example.txt).

Requirements
Python 3.6+
cryptography library (included in requirements.txt)
Note: Make sure to store your encryption/decryption passwords securely, as they cannot be recovered if lost.
