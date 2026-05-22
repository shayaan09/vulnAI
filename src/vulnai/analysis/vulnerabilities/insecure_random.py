from vulnai.analysis.vulns import VulnerabilityRule


# ============================================================
# CWE-338: Use of Cryptographically Weak PRNG
#
# Core idea:
# security-sensitive token/code generated with random instead of secrets

# For this rule, the strongest finding is:
# random.randint/random.choice/random.getrandbits -> variable named token/reset_code/session_id/otp
# Do not flag random used for games, UI effects, tests, or simulations as high severity.
# ============================================================


INSECURE_RANDOM_SOURCES = [
    # Security-sensitive variable names / contexts
    "token",
    "auth_token",
    "access_token",
    "refresh_token",
    "session",
    "session_id",
    "csrf",
    "csrf_token",
    "reset_token",
    "password_reset",
    "otp",
    "one_time_password",
    "verification_code",
    "invite_code",
    "api_key",
    "secret",
    "nonce",
    "salt",
    "key",

    # Assignment/call contexts
    "ast.Assign",
    "ast.AnnAssign",
    "ast.Call",
]


INSECURE_RANDOM_SINKS = [
    # Python random module
    "random.random",
    "random.randint",
    "random.randrange",
    "random.choice",
    "random.choices",
    "random.sample",
    "random.shuffle",
    "random.uniform",
    "random.getrandbits",
    "random.randbytes",
    "random.Random",

    # NumPy random is not for security tokens
    "numpy.random.random",
    "numpy.random.randint",
    "numpy.random.choice",
    "numpy.random.bytes",
    "np.random.random",
    "np.random.randint",
    "np.random.choice",
    "np.random.bytes",

    # UUIDs that are not ideal as secrets
    "uuid.uuid1",
    "uuid.uuid3",
    "uuid.uuid5",

    # Time-based token generation signals
    "time.time",
    "datetime.datetime.now",
]


INSECURE_RANDOM_SANITIZERS = [
    # Python secrets module
    "secrets.token_bytes",
    "secrets.token_hex",
    "secrets.token_urlsafe",
    "secrets.choice",
    "secrets.randbelow",
    "secrets.randbits",
    "secrets.SystemRandom",

    # OS cryptographic randomness
    "os.urandom",

    # UUID4 is generated from random bytes in Python,
    # but for API keys/tokens, secrets.token_urlsafe is still usually clearer.
    "uuid.uuid4",

    # cryptography library randomness often uses secure randomness internally
    "cryptography.hazmat.primitives",
]

INSECURE_RANDOM_RULE = VulnerabilityRule(
    name="Insecure Random",
    cwe="CWE-338",
    detectionType="patternBased",
    sources=INSECURE_RANDOM_SOURCES,
    sinks=INSECURE_RANDOM_SINKS,
    sanitizers=INSECURE_RANDOM_SANITIZERS,
)