from cryptography.hazmat.primitives import hashes
import time
import os

files = ['oneKb.txt', 'tenMb.txt']
hash_algorithms = ["SHA-256", "SHA-512", "SHA3-256"]


def hash(data, digest):
    start_time = time.time()
    digest.update(data)
    digest.finalize()
    dur_hash = time.time() - start_time
    return dur_hash, digest


def driver(file, hash_algo):
    fn = file
    digest = None
    if hash_algo == "SHA-256":
        digest = hashes.Hash(hashes.SHA256())
    elif hash_algo == "SHA-512":
        digest = hashes.Hash(hashes.SHA512())
    elif hash_algo == "SHA3-256":
        digest = hashes.Hash(hashes.SHA3_256())

    with open(file, 'rb') as file:
        data = file.read()

    dur_hash, d = hash(data, digest)
    print("Time taken for hashing {0} using {1}: {2}".format(
        fn, hash_algo, dur_hash))


driver(files[0], hash_algorithms[0])
