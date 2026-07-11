from vulnai.analysis.vulnerabilities.vulns import VulnerabilityRule

# ============================================================
# CWE-611: XML External Entity Injection
#
# Core idea:
# untrusted XML -> unsafe XML parser with external entities/DTD enabled
# For XXE, the high-confidence pattern is:
# request body/uploaded file → XML parser
# The safe pattern is usually:
# use defusedxml
# or configure the parser so DTDs/external entities/network access are disabled.
# ============================================================

XXE_SOURCES = [
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
    "request.query_string",

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

    # FastAPI / Starlette request input
    "Request.body",
    "Request.stream",
    "Request.form",
    "UploadFile.read",

    # CLI / env input
    "sys.argv",
    "input",
    "os.environ",
    "os.environ.get",
    "os.getenv",

    # Common project wrappers, including OWASP Benchmark Python helpers.
    "get_query_parameter",
    "get_form_parameter",
    "get_cookie_parameter",
    "get_header_parameter",

    # Network/socket input
    "socket.recv",
    "socket.recvfrom",
    "websocket.recv",
]


XXE_SINKS = [
    # xml.etree.ElementTree
    "xml.etree.ElementTree.parse",
    "xml.etree.ElementTree.fromstring",
    "xml.etree.ElementTree.XML",
    "ElementTree.parse",
    "ElementTree.fromstring",
    "ET.parse",
    "ET.fromstring",
    "ET.XML",

    # xml.dom
    "xml.dom.minidom.parse",
    "xml.dom.minidom.parseString",

    # xml.sax
    "xml.sax.parse",
    "xml.sax.parseString",
    "xml.sax.make_parser",

    # lxml
    "lxml.etree.parse",
    "lxml.etree.fromstring",
    "lxml.etree.XML",
    "lxml.etree.XMLParser",

    # pulldom
    "xml.dom.pulldom.parse",
    "xml.dom.pulldom.parseString",

    # suspicious generic XML wrappers
    "parse_xml",
    "load_xml",
    "xml_parse",
]


XXE_SANITIZERS = [
    # DefusedXML safe replacements
    "defusedxml.ElementTree.parse",
    "defusedxml.ElementTree.fromstring",
    "defusedxml.minidom.parse",
    "defusedxml.minidom.parseString",
    "defusedxml.sax.parse",
    "defusedxml.sax.parseString",
    "defusedxml.lxml.fromstring",
    "defusedxml.lxml.parse",

    # lxml safe parser configuration
    # These should count only when used in XMLParser config.
    "resolve_entities=False",
    "load_dtd=False",
    "no_network=True",
    "dtd_validation=False",

    # SAX features that disable external entities
    "feature_external_ges",
    "feature_external_pes",
    "setFeature",

    # Common custom validation helpers
    "disable_external_entities",
    "disable_dtd",
    "safe_xml_parse",
    "validate_xml",
    "is_safe_xml",
]


XXE_RULE = VulnerabilityRule(name="XML External Entity Injection",
    cwe="CWE-611",
    detectionType="taintFlow",
    sources=XXE_SOURCES,
    sinks=XXE_SINKS,
    sanitizers=XXE_SANITIZERS,
)
