from flask import request
import httpx
import requests
import urllib.request


def ssrf_001_requests_get():
    url = request.args.get("url")
    return requests.get(url)


def ssrf_002_requests_post_fstring():
    host = request.form.get("host")
    url = f"http://{host}/internal"
    return requests.post(url)


def ssrf_003_urllib_urlopen():
    callback = request.headers.get("X-Callback")
    return urllib.request.urlopen(callback)


def ssrf_004_httpx_get():
    target = request.cookies.get("target")
    return httpx.get(target)


def ssrf_005_interprocedural_sink_param():
    endpoint = request.args.get("endpoint")
    return ssrf_005_fetch(endpoint)


def ssrf_005_fetch(endpoint):
    return requests.get(endpoint)


def ssrf_006_helper_returns_url():
    endpoint = ssrf_006_get_url()
    return requests.get(endpoint)


def ssrf_006_get_url():
    return request.args.get("url")


def ssrf_007_try_body_sink():
    target = request.args.get("target")
    try:
        return requests.get(target)
    except requests.RequestException:
        return None


def ssrf_008_requests_request_keyword_url():
    target = request.args.get("target")
    return requests.request(method="GET", url=target)

