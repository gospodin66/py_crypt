from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from getpass import getpass
from sys import argv
from localrsa import rsa_encrypter;
from localaes import aes_encrypter;


# README:
# Script invokes RSA encrypter which encrypts AES key.
# Decrypted AES key is used to encrypt further messages of any len.
# RUN: python3 crypt.py "exampleuser" "We attack at dawn.."



class CryptError(Exception):
    pass



if __name__ == '__main__':
    if len(argv) < 4:
        raise CryptError("\nThis script accepts [user], [data] & [encrypted_data_path] args.")

    user = argv[1]
    data = argv[2].encode("utf-8")
    passphrase = getpass('Enter passphrase: ')
    encrypted_data_path = argv[3]
    aes_session_key = get_random_bytes(16)

    # create RSA keypair in constructor, encrypts session_key (AES)
    crypt_rsa = rsa_encrypter(user, passphrase)
    # encrypt AES session key
    encrypted_aes_session_key = crypt_rsa.encrypt(
        encrypted_data_path=encrypted_data_path,
        data=aes_session_key,
        mode='public'
    )


    # .
    # .
    # .
    

    # decrypt and use AES session key for further communication
    decrypted_aes_session_key = crypt_rsa.decrypt(
        encrypted_data_path=encrypted_data_path,
        mode='private'
    )
    crypt_aes = aes_encrypter(user, aes_session_key)
    # encrypt initial data with AES key
    # nonce, tag & ciphertext could also be read from a file
    nonce, tag, ciphertext = crypt_aes.encrypt(data)
    decrypted = crypt_aes.decrypt((nonce, tag, ciphertext))


    print(f">>> result: {decrypted.decode()}\r\n")
