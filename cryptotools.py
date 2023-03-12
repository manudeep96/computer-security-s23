from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives.ciphers import modes, Cipher, algorithms
import time
import os

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
osslbackend = openssl.backend

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


# print("\nPART a")
# driver_abc('CBC', file_names[0], 128)
# driver_abc('CBC', file_names[1], 128)

# print("\nPART b")
# driver_abc('CTR', file_names[0], 128)
# driver_abc('CTR', file_names[1], 128)

# print("\nPART c")
# driver_abc('CTR', file_names[0], 256)
# driver_abc('CTR', file_names[1], 256)


# PART d,e

def gen_RSA_key(key_size):
    start_time = time.time()
    sk = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=osslbackend)
    dur_keygen = time.time() - start_time
    pk = sk.public_key()
    return sk, pk, dur_keygen

# Break data into chunks of 223bits(190 characters) and encrypt each seperately. append it to ct after each iteration


def break_data(data, size):
    i = size
    length = len(data)
    end = False
    data_chunks = []
    while (not end):
        if i < length:
            d = data[i-size:i]
            i = i + size
        else:
            d = data[i - size:]
            end = True
        data_chunks.append(d)
    return data_chunks


def encrypt_rsa(data, pk):
    data_chunks = break_data(data, 190)
    start_time = time.time()
    ct = []
    for d in data_chunks:
        c = pk.encrypt(
            d,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        ct.append(c)
    dur_enc_rsa = time.time() - start_time
    return ct, dur_enc_rsa


def decrypt_rsa(ct, sk):
    pt = b""
    start_time = time.time()
    for c in ct:
        pt += sk.decrypt(
            c,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    dur_dec_rsa = time.time() - start_time
    return pt, dur_dec_rsa


def driver_de(file_name, key_size=2048):
    sk, pk, dur_keygen = gen_RSA_key(key_size)

    print("time taken for {0}b key generation: {1}".format(
        key_size, dur_keygen))

    # Initialize necessary classes
    with open(file_name, 'rb') as file:
        data = file.read()

    # Encryption
    ct, dur_enc_rsa = encrypt_rsa(data, pk)
    print("Encryption - file: {0}, time {1}, time/byte {2}".format(
        file_name, dur_enc_rsa, dur_enc_rsa/file_sizes[file_name]))

    # Decryption
    pt, dur_dec_rsa = decrypt_rsa(ct, sk)
    print("Decryption - file: {0}, time {1}, time/byte {2}".format(
        file_name, dur_dec_rsa, dur_dec_rsa/file_sizes[file_name]))


print("\nPART d")
driver_de(file_names[0], 2048)
driver_de(file_names[1], 2048)
