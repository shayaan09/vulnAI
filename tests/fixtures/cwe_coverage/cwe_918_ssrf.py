from flask import request
import requests
import urllib.request


def validate_url(url):
    return url


def cwe_918_requests_positive():
    url = request.args.get("url")
    return requests.get(url)


def cwe_918_interprocedural_positive():
    endpoint = request.form.get("endpoint")
    return fetch_endpoint(endpoint)


def fetch_endpoint(endpoint):
    return requests.post(endpoint)


def cwe_918_urllib_positive():
    callback = request.headers.get("X-Callback")
    return urllib.request.urlopen(callback)


def cwe_918_try_body_positive():
    target_url = request.cookies.get("target")
    try:
        return requests.get(target_url)
    except requests.RequestException:
        return None


def cwe_918_sanitized_negative():
    url = validate_url(request.args.get("url"))
    return requests.get(url)


def cwe_918_safe_negative():
    return requests.get("https://example.com/health")

