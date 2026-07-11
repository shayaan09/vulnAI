from random import randint
import numpy as np
import random
import random as rnd
import uuid


def rand_001_random_random_token():
    token = str(random.random())
    return token


def rand_002_random_randint_otp():
    otp = str(random.randint(100000, 999999))
    return otp


def rand_003_random_getrandbits_session():
    session_id = str(random.getrandbits(64))
    return session_id


def rand_004_from_import_randint():
    reset_token = str(randint(100000, 999999))
    return reset_token


def rand_005_random_alias_choice():
    api_key = rnd.choice(["alpha", "bravo", "charlie"])
    return api_key


def rand_006_random_instance_method():
    generator = random.Random()
    secret = str(generator.randint(100000, 999999))
    return secret


def rand_007_uuid1_session():
    session_id = str(uuid.uuid1())
    return session_id


def rand_008_numpy_random_alias():
    api_key = str(np.random.randint(100000, 999999))
    return api_key

