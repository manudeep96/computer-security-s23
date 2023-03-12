from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives.ciphers import modes, Cipher, algorithms
import time
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa

data = b"this is some data I'd like to sign"
file_names = ['oneKb.txt', 'tenMb.txt']


# Creates key - 2048 or 3072 bit
def gen_dsa_key(size=2048):
    start_time = time.time()
    sk = dsa.generate_private_key(key_size=size)
    dur_keygen = time.time() - start_time

    pk = sk.public_key()

    return sk, pk, dur_keygen

# Signs files


def sign_files(sk, data):
    start_time = time.time()
    signature = sk.sign(
        data,
        hashes.SHA256()
    )
    dur_sign = time.time() - start_time
    return signature, dur_sign


# Verifies signature
def verify(pk, signature, data):
    start_time = time.time()
    pk.verify(
        signature,
        data,
        hashes.SHA256()
    )
    dur_verify = time.time() - start_time
    return dur_verify


def driver_gh(file_name, key_size):

    sk, pk, dur_keygen = gen_dsa_key()
    print("time taken for {0}b key generation: {1}".format(
        key_size, dur_keygen))

    # Open the file
    with open(file_name, 'rb') as file:
        data = file.read()

    # Sign the file hash
    signature, dur_sign = sign_files(sk, data)
    print("time taken for signing {0} file: {1}".format(file_name, dur_sign))

    # Verify if the signature is valid with public key
    dur_verify = verify(pk, signature, data)
    print("time taken for verifying {0} file: {1}".format(
        file_name, dur_verify))


print("Key size - 2048 bits")
driver_gh(file_names[0], 2048)
driver_gh(file_names[1], 2048)

print("Key size - 3072 bits")
driver_gh(file_names[0], 3072)
driver_gh(file_names[1], 3072)
