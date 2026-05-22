from vulnai.analysis.vulns import VulnerabilityRule

# ============================================================
# CWE-918: Server-Side Request Forgery
#
# Core idea:
# user-controlled URL/host -> server-side HTTP request -> no URL/IP allowlist

# urlparse() alone is NOT a sanitizer. It only becomes useful if the code checks scheme, host, and resolved IP against an allowlist/blocklist.
# ============================================================


SSRF_SOURCES = [
    # Flask request input
    "request.args",
    "request.args.get",
    "request.form",
    "request.form.get",
    "request.values",
    "request.values.get",
    "request.json",
    "request.get_json",
    "request.data",
    "request.headers",
    "request.headers.get",
    "request.cookies",
    "request.cookies.get",

    # Django request input
    "request.GET",
    "request.GET.get",
    "request.POST",
    "request.POST.get",
    "request.body",
    "request.headers",
    "request.headers.get",
    "request.META",
    "request.META.get",

    # FastAPI / Starlette request input
    "Request.query_params",
    "Request.path_params",
    "Request.headers",
    "Request.cookies",
    "Request.json",
    "Request.body",

    # CLI / env / config input
    "sys.argv",
    "input",
    "os.environ",
    "os.environ.get",
    "os.getenv",
    "configparser.ConfigParser.get",

    # Common URL variable names
    "url",
    "uri",
    "endpoint",
    "callback",
    "callback_url",
    "webhook",
    "webhook_url",
    "redirect_url",
    "target",
    "target_url",
    "host",
    "hostname",
    "domain",
]


SSRF_SINKS = [
    # requests library
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.delete",
    "requests.head",
    "requests.options",
    "requests.request",
    "requests.Session.get",
    "requests.Session.post",
    "requests.Session.put",
    "requests.Session.patch",
    "requests.Session.delete",
    "requests.Session.request",

    # httpx
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.patch",
    "httpx.delete",
    "httpx.request",
    "httpx.Client.get",
    "httpx.Client.post",
    "httpx.Client.request",
    "httpx.AsyncClient.get",
    "httpx.AsyncClient.post",
    "httpx.AsyncClient.request",

    # urllib
    "urllib.request.urlopen",
    "urllib.request.Request",

    # urllib3
    "urllib3.PoolManager.request",
    "urllib3.request",

    # aiohttp
    "aiohttp.ClientSession.get",
    "aiohttp.ClientSession.post",
    "aiohttp.ClientSession.put",
    "aiohttp.ClientSession.delete",
    "aiohttp.ClientSession.request",

    # tornado
    "tornado.httpclient.HTTPClient.fetch",
    "tornado.httpclient.AsyncHTTPClient.fetch",

    # lower-level socket connections
    "socket.create_connection",
    "socket.connect",
]


SSRF_SANITIZERS = [
    # URL parsing: useful as part of validation, not enough alone
    "urllib.parse.urlparse",
    "urllib.parse.urlsplit",

    # IP/domain validation helpers
    "ipaddress.ip_address",
    "ipaddress.ip_network",
    "socket.gethostbyname",
    "socket.getaddrinfo",

    # Common validation helpers
    "validate_url",
    "validate_uri",
    "validate_host",
    "validate_domain",
    "is_safe_url",
    "is_allowed_url",
    "is_allowed_host",
    "is_allowed_domain",
    "is_public_ip",
    "is_private_ip",
    "is_loopback",
    "is_link_local",
    "is_reserved",
    "block_private_ip",
    "block_internal_ip",

    # Allowlist-style variables/functions
    "allowed_hosts",
    "allowed_domains",
    "allowed_urls",
    "url_allowlist",
    "domain_allowlist",
    "allowlist",
    "whitelist",

    # Scheme checks
    "allowed_schemes",
    "validate_scheme",
]

SSRF_RULE = VulnerabilityRule(
    name="Server-Side Request Forgery",
    cwe="CWE-918",
    detectionType="taintFlow",
    sources=SSRF_SOURCES,
    sinks=SSRF_SINKS,
    sanitizers=SSRF_SANITIZERS,
)
