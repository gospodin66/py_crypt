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
    if len(argv) < 2:
        raise CryptError("\nThis script accepts [user] arg.")

    encrypted_data_dir = '/'.join([
        os.path.dirname(__file__), 
        'ENCRYPTED-data', 
    ])

    user = argv[1]
    passphrase = getpass('Enter passphrase: ')


    encrypted_data_path = '/'.join([
        encrypted_data_dir,
        f'{user}_encrypted_data.bin'
    ])
    encrypted_key_path = '/'.join([
        encrypted_data_dir,
        f'{user}_encrypted_key.bin'
    ])

    with open(encrypted_data_path, 'rb') as f:
       encrypted_data = f.read()

    nonce = encrypted_data[0:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]

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
    # nonce, tag, ciphertext = crypt_aes_later.encrypt(data.encode('utf-8'))
    decrypted = crypt_aes_later.decrypt((nonce, tag, ciphertext))
    
    print(f">>> AES decrypted result: {decrypted}\r\n")
