from vulnai.analysis.vulns import VulnerabilityRule

# ============================================================
# CWE-327: Use of a Broken or Risky Cryptographic Algorithm
#
# Core idea:
# sensitive data -> weak crypto API
#
# This can be patternBased first, then taintFlow later.
# Important nuance: hashlib.sha256 is not always bad. It is bad when used directly for password storage. So initially, mark it as suspicious/lower confidence unless the variable names suggest password/security use.
# ============================================================


WEAK_CRYPTOGRAPHY_SOURCES = [
    # Sensitive variable names
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "access_token",
    "refresh_token",
    "private_key",
    "session_id",
    "auth_code",
    "otp",
    "pin",

    # Request/user input that may contain sensitive data
    "request.form",
    "request.form.get",
    "request.POST",
    "request.POST.get",
    "request.json",
    "request.get_json",
    "input",

    # Config/env secrets
    "os.environ",
    "os.environ.get",
    "os.getenv",
]


WEAK_CRYPTOGRAPHY_SINKS = [
    # Weak hash algorithms
    "hashlib.md5",
    "hashlib.sha1",
    "Crypto.Hash.MD5.new",
    "Crypto.Hash.SHA1.new",
    "cryptography.hazmat.primitives.hashes.MD5",
    "cryptography.hazmat.primitives.hashes.SHA1",

    # Weak / deprecated ciphers
    "Crypto.Cipher.DES.new",
    "Crypto.Cipher.ARC2.new",
    "Crypto.Cipher.ARC4.new",
    "Crypto.Cipher.Blowfish.new",
    "cryptography.hazmat.primitives.ciphers.algorithms.ARC4",
    "cryptography.hazmat.primitives.ciphers.algorithms.Blowfish",
    "cryptography.hazmat.primitives.ciphers.algorithms.IDEA",
    "cryptography.hazmat.primitives.ciphers.algorithms.TripleDES",

    # Dangerous block cipher modes
    "AES.MODE_ECB",
    "DES.MODE_ECB",
    "Crypto.Cipher.AES.MODE_ECB",
    "Crypto.Cipher.DES.MODE_ECB",
    "modes.ECB",
    "cryptography.hazmat.primitives.ciphers.modes.ECB",

    # Weak password hashing patterns
    "hashlib.sha256",
    "hashlib.sha512",
    "hashlib.pbkdf2_hmac",  # not always bad; check iteration count later

    # Suspicious custom crypto wrappers
    "encrypt",
    "decrypt",
    "hash_password",
    "make_hash",
]


WEAK_CRYPTOGRAPHY_SANITIZERS = [
    # Strong password hashing
    "bcrypt.hashpw",
    "bcrypt.checkpw",
    "argon2.PasswordHasher.hash",
    "argon2.PasswordHasher.verify",
    "hashlib.scrypt",
    "passlib.hash.bcrypt.hash",
    "passlib.hash.argon2.hash",

    # PBKDF2 can be acceptable with strong parameters
    "cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC",

    # Authenticated encryption
    "cryptography.fernet.Fernet",
    "cryptography.hazmat.primitives.ciphers.aead.AESGCM",
    "cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305",

    # Secure comparison
    "hmac.compare_digest",

    # Secure random for keys/nonces
    "secrets.token_bytes",
    "os.urandom",
]

WEAK_CRYPTOGRAPHY_RULE = VulnerabilityRule(
    name="Weak Cryptography",
    cwe="CWE-327",
    detectionType="patternBased",
    sources=WEAK_CRYPTOGRAPHY_SOURCES,
    sinks=WEAK_CRYPTOGRAPHY_SINKS,
    sanitizers=WEAK_CRYPTOGRAPHY_SANITIZERS,
)
