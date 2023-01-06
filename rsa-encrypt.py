import os

from getpass import getpass
from sys import argv
from localrsa import rsa_encrypter;
from localaes import aes_encrypter;

# RUN:
# python3 before.py {user}



class CryptError(Exception):
    pass



if __name__ == '__main__':
    if len(argv) < 2:
        raise CryptError("\nThis script accepts [user] arg.")

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

    passphrase = getpass('Enter passphrase: ')
    encrypted_key_path = '/'.join([
        encrypted_data_dir,
        f'{user}_encrypted_key.bin'
    ])
    encrypted_data_path = '/'.join([
        encrypted_data_dir,
        f'{user}_encrypted_data.bin'
    ])
    # init earlier => fetch key from file if exists
    crypt_aes = aes_encrypter(user)
    aes_session_key = crypt_aes.session_key
    # create RSA keypair in constructor -- encrypt AES session_key
    crypt_rsa = rsa_encrypter(user, passphrase)
    encrypted_aes_session_key = crypt_rsa.encrypt(
        encrypted_data_path=encrypted_key_path,
        data=aes_session_key,
        mode='public'
    )
    print(f">>> RSA encrypted AES key: {encrypted_aes_session_key}\r\n")
