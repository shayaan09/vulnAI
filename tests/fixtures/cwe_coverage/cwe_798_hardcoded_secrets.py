import os


def cwe_798_secret_key_positive():
    SECRET_KEY = "fake-live-secret-value"
    return SECRET_KEY


def cwe_798_password_positive():
    db_password = "prod-database-password-123"
    return db_password


def cwe_798_token_positive():
    github_token = "fake-github-token-value"
    return github_token


def cwe_798_attribute_positive(settings):
    settings.api_key = "fake-api-key-value"
    return settings.api_key


def cwe_798_env_negative():
    SECRET_KEY = os.environ.get("SECRET_KEY")
    return SECRET_KEY


def cwe_798_placeholder_negative():
    api_key = "your_api_key_here"
    return api_key
