import hashlib
from Crypto.Cipher import DES


def cwe_327_md5_positive():
    password = "user supplied password"
    return hashlib.md5(password.encode()).hexdigest()


def cwe_327_sha1_positive():
    token = input()
    return hashlib.sha1(token.encode()).hexdigest()


def cwe_327_interprocedural_positive():
    secret = input()
    return weak_hash(secret)


def weak_hash(secret):
    return hashlib.md5(secret.encode()).hexdigest()


def cwe_327_cipher_positive():
    key = b"12345678"
    return DES.new(key, DES.MODE_ECB)


def cwe_327_safe_negative():
    password = input()
    return hashlib.scrypt(password.encode(), salt=b"salt", n=16384, r=8, p=1)

