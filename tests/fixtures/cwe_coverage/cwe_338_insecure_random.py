import random
import secrets
import uuid


def cwe_338_token_positive():
    token = str(random.getrandbits(32))
    return token


def cwe_338_interprocedural_positive():
    return build_reset_token()


def build_reset_token():
    reset_token = str(random.randint(100000, 999999))
    return reset_token


def cwe_338_choice_positive():
    otp = random.choice(["111111", "222222", "333333"])
    return otp


def cwe_338_uuid_positive():
    session_id = str(uuid.uuid1())
    return session_id


def cwe_338_safe_negative():
    token = secrets.token_urlsafe(32)
    return token

