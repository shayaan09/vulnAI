from vulnai.analysis.vulnerabilities.vulns import VulnerabilityRule


# ============================================================
# CWE-798: Use of Hard-coded Credentials
#
# Core idea:
# secret-looking literal appears directly in source code
#
# This is mostly patternBased, not taintFlow.
# For this one, sources/sinks/sanitizers are not traditional. The analyzer is mostly checking:
# secret-like variable name + literal string value
# or:
# literal string matches known secret pattern
# ============================================================


HARDCODED_SECRET_SOURCES = [
    # AST locations where secrets commonly appear
    "ast.Assign",
    "ast.AnnAssign",
    "ast.Constant",
    "ast.Dict",
    "ast.keyword",

    # Config-style files represented in Python
    "settings.py",
    "config.py",
    ".env.example",
]


HARDCODED_SECRET_SINKS = [
    # Suspicious variable/key names
    "password",
    "passwd",
    "pwd",
    "secret",
    "secret_key",
    "SECRET_KEY",
    "api_key",
    "apikey",
    "access_key",
    "access_token",
    "auth_token",
    "refresh_token",
    "private_key",
    "client_secret",
    "consumer_secret",
    "database_url",
    "db_password",
    "smtp_password",
    "aws_access_key_id",
    "aws_secret_access_key",
    "google_api_key",
    "stripe_secret_key",
    "github_token",
    "jwt_secret",

    # Secret-looking literal patterns
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "AKIA",
    "ASIA",
    "sk_live_",
    "sk_test_",
    "ghp_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "SG.",
    "AIza",
]


HARDCODED_SECRET_SANITIZERS = [
    # Environment variables
    "os.environ",
    "os.environ.get",
    "os.getenv",

    # dotenv/config loading
    "dotenv.load_dotenv",
    "dotenv_values",
    "decouple.config",
    "environ.Env",

    # Secret managers
    "boto3.client.get_secret_value",
    "SecretClient.get_secret",
    "google.cloud.secretmanager.SecretManagerServiceClient.access_secret_version",
    "hvac.Client.secrets",
    "keyring.get_password",

    # Django/Flask config indirection
    "app.config.from_envvar",
    "app.config.from_object",

    # Placeholder/test values that should reduce confidence
    "example",
    "dummy",
    "test",
    "changeme",
    "replace_me",
    "your_api_key_here",
    "not-a-real-secret",
]


HARDCODED_SECRETS_RULE = VulnerabilityRule(
    name="Hardcoded Secrets",
    cwe="CWE-798",
    detectionType="patternBased",
    sources=HARDCODED_SECRET_SOURCES,
    sinks=HARDCODED_SECRET_SINKS,
    sanitizers=HARDCODED_SECRET_SANITIZERS,
)