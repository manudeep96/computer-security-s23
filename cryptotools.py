from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives.ciphers import modes, Cipher, algorithms
import time
import os

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric import dsa

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


print("\nPART a")
driver_abc('CBC', file_names[0], 128)
driver_abc('CBC', file_names[1], 128)

print("\nPART b")
driver_abc('CTR', file_names[0], 128)
driver_abc('CTR', file_names[1], 128)

print("\nPART c")
driver_abc('CTR', file_names[0], 256)
driver_abc('CTR', file_names[1], 256)


# PART d,e
def gen_RSA_key(key_size):
    start_time = time.time()
    sk = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=osslbackend)
    dur_keygen = (time.time() - start_time) * 1000000
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
    dur_enc_rsa = (time.time() - start_time) * 1000000
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
    dur_dec_rsa = (time.time() - start_time) * 1000000
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
print("\nPART e")
driver_de(file_names[0], 3072)
driver_de(file_names[1], 3072)


# PART f
hash_algorithms = ["SHA-256", "SHA-512", "SHA3-256"]


def hash(data, digest):
    start_time = time.time()
    digest.update(data)
    digest.finalize()
    dur_hash = (time.time() - start_time) * 1000
    return dur_hash, digest


def driver(file, hash_algo):
    fn = file
    digest = None
    if hash_algo == "SHA-256":
        digest = hashes.Hash(hashes.SHA256(), backend=osslbackend)
    elif hash_algo == "SHA-512":
        digest = hashes.Hash(hashes.SHA512(), backend=osslbackend)
    elif hash_algo == "SHA3-256":
        digest = hashes.Hash(hashes.SHA3_256(), backend=osslbackend)

    with open(file, 'rb') as file:
        data = file.read()

    dur_hash, _ = hash(data, digest)
    print("Hashing- file: {0}, algo:{1}, time {2}, time/byte {3}".format(
        fn, hash_algo, dur_hash, dur_hash/file_sizes[fn]))


print("\nPART f")
driver(file_names[0], hash_algorithms[0])
driver(file_names[1], hash_algorithms[0])

driver(file_names[0], hash_algorithms[1])
driver(file_names[1], hash_algorithms[1])

driver(file_names[0], hash_algorithms[2])
driver(file_names[1], hash_algorithms[2])


# PART g,h
# Creates key - 2048 or 3072 bit
def gen_dsa_key(size=2048):
    start_time = time.time()
    sk = dsa.generate_private_key(key_size=size, backend=osslbackend)
    dur_keygen = (time.time() - start_time) * 1000000
    pk = sk.public_key()
    return sk, pk, dur_keygen


def sign_files(sk, data):
    start_time = time.time()
    signature = sk.sign(
        data,
        hashes.SHA256()
    )
    dur_sign = (time.time() - start_time) * 1000000
    return signature, dur_sign


# Verifies signature
def verify(pk, signature, data):
    start_time = time.time()
    pk.verify(
        signature,
        data,
        hashes.SHA256()
    )
    dur_verify = (time.time() - start_time) * 1000000
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
    print("Signing - file: {0} time: {1} time/ byte".format(file_name,
          dur_sign, dur_sign/file_sizes[file_name]))

    # Verify if the signature is valid with public key
    dur_verify = verify(pk, signature, data)
    print("Verifying - file: {0} time: {1} time/ byte".format(
        file_name, dur_verify, dur_verify/file_sizes[file_name]))


print("\nPart g")
print("Key size - 2048 bits")
driver_gh(file_names[0], 2048)
driver_gh(file_names[1], 2048)
print("\nPart h")
print("Key size - 3072 bits")
driver_gh(file_names[0], 3072)
driver_gh(file_names[1], 3072)
