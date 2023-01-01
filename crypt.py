from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from getpass import getpass
from sys import argv
from localrsa import rsa_encrypter;


# README:
# Script invokes RSA encrypter which encrypts AES key.
# Decrypted AES key is used to encrypt further messages of any len.
# RUN: python3 crypt.py "exampleuser" "We attack at dawn.."



class CryptError(Exception):
    pass




class aes_encrypter:
    #
    # variables {user} & {passphrase} are not used in AES encrypter (1st)
    # instead they are simply passed to RSA encrypter (2nd)
    #
    def __init__(self, user: str, passphrase: str, encrypted_data_path: str) -> None:
        self._session_key = get_random_bytes(16)
        self._encrypted_data_out = '_'.join([user, "encrypted_data.bin"])
        self.rsa_encrypter = rsa_encrypter(user, passphrase, self._session_key, encrypted_data_path)
        self.cipher_aes = AES.new(self._session_key, AES.MODE_EAX)



    #
    # encrypts with public
    #
    def encrypt(self, data) -> tuple:

        if not isinstance(data, bytes) \
            and not isinstance(data, str) \
            and not isinstance(data, bytes) \
            and not isinstance(data, int):
            raise CryptError(f"Invalid data type [{type(data)}] for var ['data']")

        enc_session_key = self.rsa_encrypter.encrypt('public')
        ciphertext, tag = self.cipher_aes.encrypt_and_digest(data)

        with open(self._encrypted_data_out, "wb") as file_out:
            [ file_out.write(x) for x in (enc_session_key, self.cipher_aes.nonce, tag, ciphertext) ]

        print(
            f"DEBUG AES ENCRYPT SESSION KEY:\r\n"\
            f"tag: {str(tag)}\r\n"\
            f"nonce: {str(self.cipher_aes.nonce)}\r\n"\
            f"ciphertext: {str(ciphertext)}\r\n"\
            f"enc_session_key: {str(enc_session_key)}\r\n"
        )

        return self.cipher_aes.nonce, tag, ciphertext, enc_session_key


    #
    # decrypts with private
    #
    def decrypt(self) -> bytes:
        decrypted_session_key, nonce, tag, ciphertext = self.rsa_encrypter.decrypt('private')
        # create new aes cipher on the "other side" with same session_key
        temp_cipher_aes = AES.new(decrypted_session_key, AES.MODE_EAX, nonce)

        print(
            f"DEBUG AES DECRYPT SESSION KEY:\r\n"\
            f"tag: {str(tag)}\r\n"\
            f"nonce: {str(nonce)}\r\n"\
            f"ciphertext: {str(ciphertext)}\r\n"\
            f"decrypted_session_key: {str(decrypted_session_key)}\r\n"
        )

        data = temp_cipher_aes.decrypt_and_verify(ciphertext, tag)
        return data



if __name__ == '__main__':
    if len(argv) < 4:
        raise CryptError("\nThis script accepts [user], [data] & [encrypted_data_path] args.")

    user = argv[1]
    data = argv[2].encode("utf-8")
    passphrase = getpass('Enter passphrase: ')
    encrypted_data_path = argv[3]

    # creates RSA keypair in constructor, encrypts session_key (AES)
    crypt = aes_encrypter(user, passphrase, encrypted_data_path)

    # AES enc/dec
    crypt.encrypt(data)
    decrypted = crypt.decrypt()

    print(f">>> result: {decrypted.decode()}\r\n")
