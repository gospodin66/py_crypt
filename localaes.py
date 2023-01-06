import base64
import os

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from sys import argv
# from datetime import datetime

# RUN:
# python3 localaes.py ljkra ljkra



class CryptError(Exception):
    pass



class aes_encrypter:
    def __init__(self, user: str) -> None:
        self.encrypted_data_dir = '/'.join([
            os.path.dirname(__file__), 
            'ENCRYPTED-data', 
        ])
        self.keyring_dir_path = '/'.join([
            os.path.dirname(os.path.realpath(__file__)),
            "AES-keys",
        ])
        self.keyring_path = '/'.join([
            self.keyring_dir_path,
            "aes-keys.txt"
        ])

        self.user, self.user_key = self.get_key(user)
        
        self.encrypted_user_data_path = '/'.join([
            self.encrypted_data_dir,
            f'{user}_encrypted_data.bin'
        ])
        self.cipher_aes = AES.new(self.user_key, AES.MODE_EAX)


    #
    # read/append key to the list
    #
    def get_key(self, user: str) -> tuple:
        try:
            if not os.path.isdir(self.keyring_dir_path):
                print(f'Generating new directory {self.keyring_dir_path}')
                os.makedirs(self.keyring_dir_path)
        except CryptError as e:
            raise CryptError(f"Error creating directory: {e.args[::-1]}")
            
        _user, _user_key = self.read_key_file(user)
        if _user and _user_key:
            print(f"User {_user} exists with key: {_user_key}")
            return _user, _user_key

        _user, _user_key = (user, get_random_bytes(16))
        print(f"User {_user} doesn't exist. Adding to keyring..")
        with open(self.keyring_path, 'a') as f:
            f.write(':'.join([
                    user,
                    f'{base64.b64encode(_user_key).decode("utf-8")}\n'
                ])
            )
        print(f"Key added to keyring")
        return _user, _user_key


    #
    #
    #
    def read_key_file(self, user: str) -> tuple:
        if os.path.exists(self.keyring_path):
            with open(self.keyring_path, 'r') as f:
                lines = f.readlines()
                for line in lines:
                    _user = line.split(':')[0]
                    _user_key = line.split(':')[1]
                    if user == _user:
                        return _user, base64.b64decode(_user_key)
        return None, None
    #
    # encrypts with public
    #
    def encrypt(self, data) -> tuple:

        if not isinstance(data, (bytes, str, bytes, int)):
            raise CryptError(f"Invalid data type [{str(type(data))}] for var ['data']")

        ciphertext, tag = self.cipher_aes.encrypt_and_digest(data)

        with open(self.encrypted_user_data_path, "wb") as file_out:
            [ file_out.write(x) for x in (self.cipher_aes.nonce, tag, ciphertext) ]

        print(
            f"DEBUG AES ENCRYPT DATA:\r\n"\
            f"nonce: {str(self.cipher_aes.nonce)}\r\n"\
            f"tag: {str(tag)}\r\n"\
            f"ciphertext: {str(ciphertext)}\r\n"\
        )

        return self.cipher_aes.nonce, tag, ciphertext


    #
    # decrypts with private
    #
    def decrypt(self, encrypted: tuple) -> bytes:
        nonce = encrypted[0]
        tag = encrypted[1]
        ciphertext = encrypted[2]

        # create new aes cipher on the "other side" with same session_key
        cipher = AES.new(self.user_key, AES.MODE_EAX, nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)

        print(
            f"DEBUG AES DECRYPT SESSION KEY:\r\n"\
            f"nonce: {str(nonce)}\r\n"\
            f"tag: {str(tag)}\r\n"\
            f"ciphertext: {str(ciphertext)}\r\n"\
            f"decrypted data: {data}\r\n"
        )

        return data



if __name__ == '__main__':
    if len(argv) < 3:
        raise CryptError("\nThis script accepts ['user'] & ['data'] args.")

    user = argv[1]
    data = argv[2].encode("utf-8")

    crypt = aes_encrypter(user)
    encrypted = crypt.encrypt(data)
    decrypted = crypt.decrypt(encrypted)

    print(f">>> result: {decrypted.decode()}\r\n")
