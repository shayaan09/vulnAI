from Crypto.Cipher import ARC4, DES
from hashlib import md5
import hashlib
import hashlib as hl


def crypto_001_hashlib_md5():
    password = "correct horse battery staple"
    return hashlib.md5(password.encode()).hexdigest()


def crypto_002_hashlib_sha1():
    token = input()
    return hashlib.sha1(token.encode()).hexdigest()


def crypto_003_hashlib_alias():
    secret = input()
    return hl.md5(secret.encode()).hexdigest()


def crypto_004_from_import_md5():
    password = input()
    return md5(password.encode()).hexdigest()


def crypto_005_des_cipher():
    key = b"12345678"
    return DES.new(key, DES.MODE_ECB)


def crypto_006_arc4_cipher():
    key = b"weak-key"
    return ARC4.new(key)


def crypto_007_custom_hash_password_wrapper():
    password = input()
    return hash_password(password)


def hash_password(password):
    return password


def crypto_008_sha256_password_storage():
    password = input()
    return hashlib.sha256(password.encode()).hexdigest()

