import cryptography
import time
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import sys

file_names = ['oneKb.txt', 'tenMb.txt']


def gen_RSA_key(key_size):
    start_time = time.time()
    sk = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
        public_exponent=65537, key_size=key_size)
    dur_keygen = time.time() - start_time
    pk = sk.public_key()
    return sk, pk, dur_keygen

    # Break data into chunks of 223bits(190 characters) and encrypt each seperately. Concatenate it to ct after each iteration


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
    # Cipher of 223 bits is 289 bits.
    # ct_chunks = break_data(ct, 289)
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
        # data = b"encrypted data"
        # data = data[190:380]
    # print(data)

    # Encryption
    ct, dur_enc_rsa = encrypt_rsa(data, pk)
    print("Time take for {0} encryption of file {1}: {2}".format(
        "RSA", file_name, dur_enc_rsa))

    # Decryption
    pt, dur_dec_rsa = decrypt_rsa(ct, sk)
    print(pt)
    print("Time take for {0} decryption of file {1}: {2}".format(
        "RSA", file_name, dur_dec_rsa))


# mode, filename, key size
# driver_abc('CBC', file_names[0], 256)
driver_de(file_names[0], 2048)

# driver_de(file_names[0], 3072)
