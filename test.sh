#!/bin/sh

user=$1

if [ -z "$user" ]; then
    echo "Missing user arg"
    exit 1
fi

echo "Testing crypt.py for user: $user"
python3 crypt.py "$user" "This is test data"
echo "Testing localrsa.py for user: $user"
python localrsa.py "$user" "This is sample data" /home/cheki/projects/py_aes_rsa/ENCRYPTED-data/"$"user_encrypted_data.bin
echo "Testing localaes.py for user: $user"
python localaes.py "$user" "This is some sample data"
echo "Testing rsa-encrypt.py for user: $user"
python rsa-encrypt.py "$user"
echo "Testing rsa-decrypt-aes-encrypt.py for user: $user"
python rsa-decrypt-aes-encrypt.py "$user" "This is classified!"
echo "Testing rsa-decrypt-aes-decrypt.py for user: $user"
python rsa-decrypt-aes-decrypt.py "$user"
echo "Testing crypt.py [jpg] for user: $user"
python3 crypt.py "$user" assets/example.jpg
echo "Testing crypt.py [gif] for user: $user"
python3 crypt.py "$user" assets/example.gif

echo "Done"
exit 0
