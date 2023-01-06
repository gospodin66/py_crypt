#!/bin/sh

echo "Testing.."

python3 crypt.py ljkra "This is test data"

python localrsa.py testuser0 "This is sample data" /home/cheki/projects/py_aes_rsa/ENCRYPTED-data/testuser0_encrypted_data.bin
python localaes.py testuser0 "This is some sample data"

python rsa-encrypt.py testuser0
python rsa-decrypt-aes-encrypt.py testuser0 "This is classified!"
python rsa-decrypt-aes-decrypt.py testuser0

python3 crypt.py ljkra assets/c.jpg