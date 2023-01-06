import os

from Crypto.Random import get_random_bytes
from getpass import getpass
from sys import argv
from localrsa import rsa_encrypter;
from localaes import aes_encrypter;


# README:
# Script invokes RSA encrypter which encrypts AES key.
# Decrypted AES key is used to encrypt further messages of any len.
# RSA encrypter encrypts/decrypts to/from file
# AES encrypter encrypts direct value

# RUN:
# python3 localaes.py "ljkrazesci" "pravi rklja" "`pwd`/RSA-keys/ljkrazesci_encrypted_data.bin"



class CryptError(Exception):
    pass



if __name__ == '__main__':
    if len(argv) < 3:
        raise CryptError("\nThis script accepts [user] & [data] args.")

    encrypted_data_dir = '/'.join([
        os.path.dirname(__file__), 
        'ENCRYPTED-data', 
    ])
    
    try:
        if not os.path.isdir(encrypted_data_dir):
            print(f'Generating new directory {encrypted_data_dir}')
            os.makedirs(encrypted_data_dir)
    except CryptError as e:
        raise CryptError(f"Error creating directory: {e.args[::-1]}")


    user = argv[1]
    data = argv[2].encode("utf-8")
    passphrase = getpass('Enter passphrase: ')
    encrypted_data_path = '/'.join([
        encrypted_data_dir,
        f'{user}_encrypted_data.bin'
    ])

    # init earlier => fetch key from file if exists
    crypt_aes = aes_encrypter(user)
    aes_session_key = crypt_aes.user_key
    # create RSA keypair in constructor -- encrypt AES session_key
    crypt_rsa = rsa_encrypter(user, passphrase)
    encrypted_aes_session_key = crypt_rsa.encrypt(
        encrypted_data_path=encrypted_data_path,
        data=aes_session_key,
        mode='public'
    )
    print(f">>> encrypted result: {encrypted_aes_session_key}\r\n")


    # .
    # .
    # .
    
    crypt_rsa_later = rsa_encrypter(user, passphrase)
    # decrypt and use AES session key for further communication
    decrypted_aes_session_key = crypt_rsa_later.decrypt(
        encrypted_data_path=encrypted_data_path,
        mode='private'
    )
    crypt_aes_later = aes_encrypter(user)
    # encrypt initial data with AES key
    # nonce, tag & ciphertext could also be read from a file
    nonce, tag, ciphertext = crypt_aes_later.encrypt(data)
    decrypted = crypt_aes_later.decrypt((nonce, tag, ciphertext))


    print(f">>> result: {decrypted.decode()}\r\n")
