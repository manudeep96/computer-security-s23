from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives.ciphers import modes, Cipher, algorithms
import time
import os
from cryptography.fernet import Fernet


def genKey128():
    start_time = time.time()
    key = os.urandom(16)
    dur_keygen = time.time() - start_time
    return key, dur_keygen
 # Encryption


def genIv128():
    iv = os.urandom(16)
    return iv


def encrypt_cbc(encryptor, data):
    start_time = time.time()
    ct = encryptor.update(data) + encryptor.finalize()

    dur_enc_cbc = time.time() - start_time
    return ct, dur_enc_cbc


def decrypt_cbc(decryptor, ct):
    start_time = time.time()
    pt = decryptor.update(ct) + decryptor.finalize()
    dur_dec_cbc = time.time() - start_time
    return pt, dur_dec_cbc


def driver_a():
    # Create key and IV
    key128, dur_keygen_128 = genKey128()
    print("time taken for key generation", dur_keygen_128)
    iv = genIv128()
    osslbackend = openssl.backend

    # Initialize necessary classes
    cipher = Cipher(algorithms.AES(key128), modes.CBC(iv), osslbackend)
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()
    with open('tenMb.txt', 'rb') as file:
        data = file.read()

    # Encryption
    ct, dur_enc_cbc = encrypt_cbc(encryptor, data)
    print("Time take for encryption", dur_enc_cbc)

    # Decryption
    pt, dur_dec_cbc = decrypt_cbc(decryptor, ct)
    print("Time take for decryption", dur_dec_cbc)


driver_a()
