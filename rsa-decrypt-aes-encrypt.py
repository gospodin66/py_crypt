import os

from getpass import getpass
from sys import argv
from localrsa import rsa_encrypter;
from localaes import aes_encrypter;

# RUN:
# python3 later.py {user} {data}



class CryptError(Exception):
    pass



if __name__ == '__main__':
    if len(argv) < 3:
        raise CryptError("\nThis script accepts [user] & [data] args.")

    encrypted_data_dir = '/'.join([
        os.path.dirname(__file__), 
        'ENCRYPTED-data', 
    ])

    user = argv[1]
    data = argv[2]

    passphrase = getpass('Enter passphrase: ')
    encrypted_data_path = '/'.join([
        encrypted_data_dir,
        f'{user}_encrypted_data.bin'
    ])
    encrypted_key_path = '/'.join([
        encrypted_data_dir,
        f'{user}_encrypted_key.bin'
    ])
    crypt_rsa_later = rsa_encrypter(user, passphrase)
    # decrypt and use AES session key for further communication
    decrypted_aes_session_key = crypt_rsa_later.decrypt(
        encrypted_data_path=encrypted_key_path,
        mode='private'
    )

    print(f">>> RSA decrypted AES key: {decrypted_aes_session_key}")

    crypt_aes_later = aes_encrypter(user, decrypted_aes_session_key)
    # encrypt initial data with AES key
    # nonce, tag & ciphertext could also be read from a file
    nonce, tag, ciphertext = crypt_aes_later.encrypt(data.encode('utf-8'))
    
    print(f">>> AES encrypted result: {(nonce, tag, ciphertext)}\r\n")
