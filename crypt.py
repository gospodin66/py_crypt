import os
import subprocess

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
# python3 crypt.py {user} {data|file}



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
    data_path = argv[2]

    if os.path.exists(data_path) and os.path.isfile(data_path):
        print(f'Provided arg [{os.path.abspath(data_path)}] is a file -- reading from file')
        file_data = b''
        with open(data_path, 'rb') as f:
            file_data += f.read()
        data = file_data
    else:
        data = data_path.encode("utf-8")

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
    crypt_aes = aes_encrypter(user=user, session_key=b'', passphrase=passphrase)
    aes_session_key = crypt_aes.session_key
    # create RSA keypair in constructor -- encrypt AES session_key
    crypt_rsa = rsa_encrypter(user, passphrase)
    encrypted_aes_session_key = crypt_rsa.encrypt(
        encrypted_data_path=encrypted_key_path,
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
        encrypted_data_path=encrypted_key_path,
        mode='private'
    )
    crypt_aes_later = aes_encrypter(user=user, session_key=b'', passphrase=passphrase)
    # encrypt initial data with AES key
    # nonce, tag & ciphertext could also be read from a file
    nonce, tag, ciphertext = crypt_aes_later.encrypt(data)
    decrypted = crypt_aes_later.decrypt((nonce, tag, ciphertext))

    if os.path.exists(data_path) and os.path.isfile(data_path):

        mime_type = subprocess.check_output(['file', '-b', '--mime', os.path.abspath(data_path)]).decode('utf-8').split(';')[0]

        print(f"\r\nDEBUG: mime-type: {mime_type}\r\n")

        # TODO: more mimetypes, better mime implementation
        if mime_type == 'image/jpeg' \
        or mime_type == 'image/jpg' \
        or mime_type == 'image/png' \
        or mime_type == 'image/gif':
            mime = mime_type.split('/')[1]


        file_out_path = '/'.join([
            os.path.dirname(os.path.abspath(data_path)),
            f'{user}_decrypted_data.{mime}'
        ])
        print(f'Decrypted file: [{file_out_path}]')
        with open(file_out_path, 'wb') as f:
            f.write(decrypted)

    else:
        print(f">>> result: {decrypted}\r\n")
