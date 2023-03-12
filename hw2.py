from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives.ciphers import modes, Cipher, algorithms
import time
import os
from cryptography.fernet import Fernet

file_names = ['oneKb.txt', 'tenMb.txt']


def gen_key(key_size):
    start_time = time.time()
    key = os.urandom(int(key_size/8))
    dur_keygen = time.time() - start_time
    return key, dur_keygen
 # Encryption


def gen_iv():
    iv = os.urandom(int(128/8))
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


def driver_abc(mode, file_name, key_size):
    # Which mode?
    if mode == "CBC":
        m = modes.CBC
    elif mode == "CTR":
        m = modes.CTR

    # Create key and IV
    key, dur_keygen = gen_key(key_size)
    print("time taken for {0}b key generation: {1}".format(
        key_size, dur_keygen))

    # IV is always block size of the Enc algorithm
    iv = gen_iv()
    osslbackend = openssl.backend

    # Initialize necessary classes
    cipher = Cipher(algorithms.AES(key), m(iv), osslbackend)
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()
    with open(file_name, 'rb') as file:
        data = file.read()

    # Encryption
    ct, dur_enc_cbc = encrypt_cbc(encryptor, data)
    print("Time take for {0} encryption of file {1}: {2}".format(
        mode, file_name, dur_enc_cbc))

    # Decryption
    pt, dur_dec_cbc = decrypt_cbc(decryptor, ct)
    print("Time take for {0} decryption of file {1}: {2}".format(
        mode, file_name, dur_dec_cbc))


# mode, filename, key size
driver_abc('CBC', file_names[1], 256)
# driver_a('CTR', file_names[1], 128)
