from vulnai.analysis.vulnerabilities.vulns import VulnerabilityRule

# ============================================================
# CWE-502: Insecure Deserialization
#
# Core idea:
# untrusted serialized data -> unsafe deserialization function
#this rule should be high-confidence when you see: request/body/file/socket input → pickle.loads / pickle.load
# ============================================================


INSECURE_DESERIALIZATION_SOURCES = [
    # Flask request input
    "request.data",
    "request.get_data",
    "request.body",
    "request.stream",
    "request.files",
    "request.files.get",
    "request.form",
    "request.form.get",
    
    "request.form.getlist",
    "request.form.keys",
    "request.args",
    "request.args.get",
    "request.args.getlist",
    "request.args.keys",
    "request.values",
    "request.values.get",
    "request.values.getlist",
    "request.values.keys",
    "request.cookies",
    "request.cookies.get",
    "request.cookies.getlist",
    "request.cookies.keys",
    "request.headers",
    "request.headers.get",
    "request.headers.getlist",
    "request.headers.keys",
    "request.get_json",
    "request.json",

    # Django request input
    "request.body",
    "request.read",
    "request.FILES",
    "request.POST",
    "request.POST.get",
    "request.POST.getlist",
    "request.POST.keys",
    "request.GET",
    "request.GET.get",
    "request.GET.getlist",
    "request.GET.keys",
    "request.COOKIES",
    "request.COOKIES.get",
    "request.COOKIES.keys",
    "request.headers",
    "request.headers.get",
    "request.headers.keys",

    # FastAPI / Starlette request input
    "Request.body",
    "Request.stream",
    "Request.form",
    "Request.json",
    "UploadFile.read",

    "get_query_parameter",
    "get_form_parameter",
    "get_cookie_parameter",
    "get_header_parameter",

    # CLI / file / environment input
    "sys.argv",
    "input",
    "open",
    "Path.read_bytes",
    "Path.read_text",
    "os.environ",
    "os.environ.get",
    "os.getenv",

    # Encoded user-controlled data
    "base64.b64decode",
    "binascii.unhexlify",

    # Network/socket input
    "socket.recv",
    "socket.recvfrom",
    "websocket.recv",

    # Cache/database/message queue data
    # Lower confidence unless the analyzer knows the data is attacker-controlled.
    "redis.Redis.get",
    "memcache.Client.get",
    "pymongo.collection.Collection.find_one",
    "sqlite3.Cursor.fetchone",
    "sqlite3.Cursor.fetchall",
]


INSECURE_DESERIALIZATION_SINKS = [
    # Python pickle family
    "pickle.load",
    "pickle.loads",
    "_pickle.load",
    "_pickle.loads",

    # Pickle-compatible libraries
    "dill.load",
    "dill.loads",
    "cloudpickle.load",
    "cloudpickle.loads",

    # Shelve uses pickle internally
    "shelve.open",

    # Joblib often relies on pickle-like loading
    "joblib.load",

    # ML/data loading APIs that may deserialize Python objects
    "torch.load",
    "numpy.load",
    "pandas.read_pickle",

    # Unsafe YAML loading
    "yaml.load",
    "ruamel.yaml.YAML.load",

    # Marshal is not safe for untrusted data
    "marshal.load",
    "marshal.loads",

    # Generic suspicious custom wrappers
    "deserialize",
    "unsafe_deserialize",
    "load_object",
    "loads_object",
    "restore_object",
]


INSECURE_DESERIALIZATION_SANITIZERS = [
    # Safe alternatives for plain data
    "json.load",
    "json.loads",
    "ast.literal_eval",

    # Safer YAML loading
    "yaml.safe_load",
    "yaml.CSafeLoader",
    "yaml.SafeLoader",

    # Signature/HMAC verification before deserialization
    # These should only count if they happen before the unsafe load.
    "hmac.compare_digest",
    "verify_signature",
    "verify_hmac",
    "validate_signature",
    "check_signature",
    "is_signed",
    "itsdangerous.Serializer.loads",
    "itsdangerous.URLSafeSerializer.loads",

    # Custom validators
    "validate_serialized_data",
    "validate_payload",
    "is_trusted_payload",
    "is_allowed_type",
    "allowed_classes",
    "allowlist",
    "whitelist",
]

INSECURE_DESERIALIZATION_RULE = VulnerabilityRule(
    name="Insecure Deserialization",
    cwe="CWE-502",
    detectionType="taintFlow",
    sources=INSECURE_DESERIALIZATION_SOURCES,
    sinks=INSECURE_DESERIALIZATION_SINKS,
    sanitizers=INSECURE_DESERIALIZATION_SANITIZERS,
)
