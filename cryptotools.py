from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives.ciphers import modes, Cipher, algorithms
import time
import os

file_names = ['oneKb.txt', 'tenMb.txt']
file_sizes = {"oneKb.txt": 1024, 'tenMb.txt': 1048576}

# PARTS a,b,c


def gen_key_aes(key_size):
    start_time = time.time()
    key = os.urandom(int(key_size/8))
    dur_keygen = (time.time() - start_time) * 1000000

    return key, dur_keygen


def gen_iv():
    iv = os.urandom(int(128/8))
    return iv


def encrypt_aes(encryptor, data):
    start_time = time.time()
    ct = encryptor.update(data) + encryptor.finalize()

    dur_enc_aes = (time.time() - start_time) * 1000000
    return ct, dur_enc_aes


def decrypt_aes(decryptor, ct):
    start_time = time.time()
    pt = decryptor.update(ct) + decryptor.finalize()
    dur_dec_aes = (time.time() - start_time) * 1000000
    return pt, dur_dec_aes


def driver_abc(mode, file_name, key_size):
    # Which mode?
    if mode == "CBC":
        m = modes.CBC
    elif mode == "CTR":
        m = modes.CTR

    # Create key and IV
    key, dur_keygen = gen_key_aes(key_size)
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
    ct, dur_enc_aes = encrypt_aes(encryptor, data)
    print("Encryption - mode: {0} file: {1} duration: {2} time/byte: {3}".format(
        mode, file_name, dur_enc_aes, dur_enc_aes/file_sizes[file_name]))

    # Decryption
    _, dur_dec_aes = decrypt_aes(decryptor, ct)
    print("Decryption - mode: {0} file: {1} duration: {2} time/byte: {3}".format(
        mode, file_name, dur_dec_aes, dur_dec_aes/file_sizes[file_name]))


print("\n PART a")
driver_abc('CBC', file_names[0], 128)
driver_abc('CBC', file_names[1], 128)

print("\n PART b")
driver_abc('CTR', file_names[0], 128)
driver_abc('CTR', file_names[1], 128)

print("\n PART c")
driver_abc('CTR', file_names[0], 256)
driver_abc('CTR', file_names[1], 256)
