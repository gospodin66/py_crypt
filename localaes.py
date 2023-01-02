import os

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from getpass import getpass
from sys import argv


class CryptError(Exception):
    pass


class aes_encrypter:
    #
    # pure AES encrypter (NO RSA)
    #
    def __init__(self, user: str, user_key: bytes = b'') -> None:
        self._user_key = user_key if user_key else get_random_bytes(16)
        self._keyring_dir_path = '/'.join([
            os.path.dirname(os.path.realpath(__file__)),
            "AES-keys",
        ])
        self._keyring_path = '/'.join([ self._keyring_dir_path, "aes-keys.txt" ])
        self._encrypted_data_out = '_'.join([user, "encrypted_data.bin"])
        self.cipher_aes = AES.new(self._user_key, AES.MODE_EAX)
        __user, __user_key = self.get_key(user, self._user_key)
        if not (__user, __user_key):
            raise CryptError("Error adding key to keyring.")
        print(f"Key added to keyring")


    #
    # append key to the list
    #
    def get_key(self, user: str, user_key: bytes) -> tuple:
        encoding = 'utf-8'

        try:
            if not os.path.isdir(self._keyring_dir_path):
                print(f'Generating new directory {self._keyring_dir_path}')
                os.makedirs(self._keyring_dir_path)
        except CryptError as e:
            raise CryptError(f"Error creating directory: {e.args[::-1]}")
            
        if os.path.exists(self._keyring_path):
            with open(self._keyring_path, 'rb') as f:
                line = f.read().decode()
                _user = line.split(': ')[0].strip().encode(encoding)
                _user_key = line.split(': ')[1].strip().encode(encoding)
                if _user == user and _user_key == user_key:
                    print(f"User {_user} exists with key: {_user_key}")
                    return _user, _user_key

        print(f"User {_user} doesn't exist. Adding to keyring..")
        _user = user.encode(encoding)
        _user_key = user_key
        with open(self._keyring_path, 'ab') as f:
            f.write(f'{user}: {user_key}\n'.encode(encoding))

        return _user, _user_key


    #
    # encrypts with public
    #
    def encrypt(self, data) -> tuple:

        if not isinstance(data, (bytes, str, bytes, int)):
            raise CryptError(f"Invalid data type [{str(type(data))}] for var ['data']")

        ciphertext, tag = self.cipher_aes.encrypt_and_digest(data)

        with open(self._encrypted_data_out, "wb") as file_out:
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
        cipher = AES.new(self._user_key, AES.MODE_EAX, nonce)

        print(
            f"DEBUG AES DECRYPT SESSION KEY:\r\n"\
            f"nonce: {str(nonce)}\r\n"\
            f"tag: {str(tag)}\r\n"\
            f"ciphertext: {str(ciphertext)}\r\n"
        )

        data = cipher.decrypt_and_verify(ciphertext, tag)
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
