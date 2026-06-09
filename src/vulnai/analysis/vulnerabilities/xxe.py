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

    # Django request input
    "request.body",
    "request.read",
    "request.FILES",
    "request.POST",
    "request.POST.get",

    # FastAPI / Starlette request input
    "Request.body",
    "Request.stream",
    "Request.form",
    "UploadFile.read",

    # CLI / file / env input
    "sys.argv",
    "input",
    "open",
    "Path.read_text",
    "Path.read_bytes",
    "os.environ",
    "os.environ.get",
    "os.getenv",

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