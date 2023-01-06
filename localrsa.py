import os

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from getpass import getpass
from sys import argv


# README:
# Script invokes RSA encrypter which encrypts AES key.
# Decrypted AES key is used to encrypt further messages of any len.
# RUN: python3 crypt.py "exampleuser" "We attack at dawn.."


class CryptError(Exception):
    pass



class rsa_encrypter:
    def __init__(self, user: str, passphrase: str) -> None:
        self._keysize = 2048
        self._keypair_path = '/'.join([
            os.path.dirname(os.path.realpath(__file__)),
            "RSA-keys",
            user
        ])
        self._priv_path = '/'.join([ self._keypair_path, 'private.pem' ])
        self._pub_path = '/'.join([ self._keypair_path, 'public.pem' ])

        try:
            self.get_key(passphrase)
            if not self.private_key or not self.public_key:
                raise CryptError(f"Malformed keypair: PUB|PRIV {self.public_key}|{self.private_key}")
        except ValueError as e:
            raise CryptError(f"Invalid passphrase: {e.args[::-1]}")
        except CryptError as e:
            raise CryptError(f"Unexpected error on fetching key: {e.args[::-1]}")
        
        self.cipher_rsa_public = PKCS1_OAEP.new(self.public_key)
        self.cipher_rsa_private = PKCS1_OAEP.new(self.private_key)


    def get_key(self, passphrase: str) -> int:
        if self._keypair_path \
            and os.path.isfile(self._priv_path) \
            and os.path.isfile(self._pub_path):

            print(f'Using existing keypair from [{self._keypair_path}]')

            try:
                with open(self._priv_path, 'r') as f:
                    self.private_key = RSA.importKey(extern_key=f.read(), passphrase=passphrase)
                    print("RSA private key initialized.")
                with open(self._pub_path, 'r') as f:
                    self.public_key = RSA.importKey(extern_key=f.read(), passphrase=passphrase)
                    print("RSA public key initialized.")
            except ValueError as e:
                raise CryptError(f'Invalid RSA keypair: {e.args[::-1]}')
            except CryptError as e:
                raise CryptError(f'Error fetching RSA keypair: {e.args[::-1]}')
            
        else:
            print(f'Generating new directory {self._keypair_path}')
            try:
                os.makedirs(self._keypair_path)
            except CryptError as e:
                raise CryptError(f"Error creating directory: {e.args[::-1]}")
            
            print(f'Generating new keypair of size {self._keysize}')
            self.private_key = RSA.generate(self._keysize)

            with open(self._priv_path, 'wb') as f:
                f.write(self.private_key.exportKey(passphrase=passphrase, pkcs=8))
            with open(self._pub_path, 'wb') as f:
                f.write(self.private_key.publickey().exportKey(passphrase=passphrase, pkcs=8))
            # init public key
            with open(self._pub_path, 'rb') as f:
                self.public_key = RSA.importKey(extern_key=f.read(), passphrase=passphrase)
                print("RSA public key re-initialized.")

        return 0


    def encrypt(self,
        encrypted_data_path: str,
        data: bytes,
        mode: str='public'
    ) -> bytes:
        if mode == 'private':
            encrypted_data = self.cipher_rsa_private.encrypt(data)
        elif mode == 'public':
            encrypted_data = self.cipher_rsa_public.encrypt(data)
        else:
            raise CryptError("Invalid RSA encryption mode")

        with open(encrypted_data_path, "wb") as f:
            f.write(encrypted_data)

        return encrypted_data


    def decrypt(self,
        encrypted_data_path: str,
        mode: str='private'
    ) -> bytes:
        decrypted_data = b''
        with open(encrypted_data_path, "rb") as file_out:
            if mode == 'private':
                decrypted_data = self.cipher_rsa_private.decrypt(file_out.read())
            else:
                decrypted_data = self.cipher_rsa_public.decrypt(file_out.read())
        return decrypted_data


if __name__ == '__main__':
    if len(argv) < 4:
        raise CryptError("\nThis script accepts [user], [data] & [keypair_dir] args.")

    user = argv[1]
    data = argv[2].encode("utf-8")
    keypair_dir = argv[3]

    passphrase = getpass('Enter passphrase: ')

    mode_encrypt = "public"
    mode_decrypt = "private"

    crypt = rsa_encrypter(user, passphrase)
    crypt.encrypt(keypair_dir, data, mode_encrypt)
    decrypted_data = crypt.decrypt(keypair_dir, mode_decrypt)

    print(f">>> result: {decrypted_data}\r\n")
