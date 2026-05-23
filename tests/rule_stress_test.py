import ast
import io
import contextlib

from vulnai.analysis.cfg import ControlFlowGraph as cfg
from vulnai.analysis.builder import Builder
from vulnai.analysis.reachingdef import ReachingDefinitionAnalyzer
from vulnai.analysis.usedef import UseDefAnalyzer
from vulnai.analysis.dfg_edge import DataFlowGraph as dfg
from vulnai.analysis.dfg import TaintAnalyzer

from vulnai.analysis.vulnerabilities.command_injection import COMMAND_RULE
from vulnai.analysis.vulnerabilities.hardcoded_secrets import HARDCODED_SECRETS_RULE
from vulnai.analysis.vulnerabilities.insecure_deserialization import INSECURE_DESERIALIZATION_RULE
from vulnai.analysis.vulnerabilities.path_traversal import PATH_TRAVERSAL_RULE
from vulnai.analysis.vulnerabilities.insecure_random import INSECURE_RANDOM_RULE
from vulnai.analysis.vulnerabilities.sqli import SQLI_RULE
from vulnai.analysis.vulnerabilities.ssrf import SSRF_RULE
from vulnai.analysis.vulnerabilities.weak_cryptography import WEAK_CRYPTOGRAPHY_RULE
from vulnai.analysis.vulnerabilities.xss import XSS_RULE
from vulnai.analysis.vulnerabilities.xxe import XXE_RULE


ALL_RULES = [
    SQLI_RULE,
    COMMAND_RULE,
    PATH_TRAVERSAL_RULE,
    XSS_RULE,
    INSECURE_DESERIALIZATION_RULE,
    HARDCODED_SECRETS_RULE,
    WEAK_CRYPTOGRAPHY_RULE,
    INSECURE_RANDOM_RULE,
    SSRF_RULE,
    XXE_RULE,
]


EXPECTED_PER_RULE = {
    "SQLi": 100,
    "Command Injection": 100,
    "Path Traversal": 100,
    "Cross-site Scripting": 100,
    "Insecure Deserialization": 100,
    "Hardcoded Secrets": 100,
    "Weak Cryptography": 100,
    "Insecure Random": 100,
    "Server-Side Request Forgery": 100,
    "XML External Entity Injection": 100,
}


def make_tainted_value(prefix, i):
    shapes = [
        f'{prefix}_src_{i} = input("{prefix} {i}: ")\n',
        f'{prefix}_src_{i} = input("{prefix} {i}: ").strip()\n',
        f'{prefix}_raw_{i} = input("{prefix} {i}: ")\n{prefix}_src_{i} = {prefix}_raw_{i}\n',
        f'{prefix}_raw_{i} = input("{prefix} {i}: ")\n{prefix}_mid_{i} = {prefix}_raw_{i}\n{prefix}_src_{i} = {prefix}_mid_{i}\n',
        f'{prefix}_src_{i} = str(input("{prefix} {i}: "))\n',
    ]
    return shapes[i % len(shapes)]


def make_test_code():
    code = []

    # ============================================================
    # 1. SQLi: 100 variants
    # ============================================================

    sqli_sinks = [
        "cursor.execute",
        "cursor.executemany",
        "cursor.executescript",
        "connection.execute",
        "db.session.execute",
        "session.execute",
        "conn.execute",
        "engine.execute",
        "pd.read_sql",
        "duckdb.execute",
    ]

    for i in range(100):
        code.append(make_tainted_value("sqli", i))
        src = f"sqli_src_{i}"
        q = f"sqli_query_{i}"

        builders = [
            f'{q} = "SELECT * FROM users WHERE id = " + {src}\n',
            f'{q} = "DELETE FROM users WHERE name = \'" + {src} + "\'"\n',
            f'{q} = f"SELECT * FROM users WHERE email = \'{{{src}}}\'"\n',
            f'{q} = "SELECT * FROM users WHERE username = {{}}".format({src})\n',
            f'{q} = "SELECT * FROM users WHERE username = \'%s\'" % {src}\n',
            f'{q} = "SELECT * FROM " + {src}\n',
            f'{q} = "SELECT * FROM users ORDER BY " + {src}\n',
            f'{q} = "SELECT * FROM logs LIMIT " + {src}\n',
            f'{q}_a = {src}\n{q} = "SELECT * FROM accounts WHERE id=" + {q}_a\n',
            f'{q}_a = {src}\n{q}_b = {q}_a\n{q} = "SELECT * FROM reports WHERE id=" + {q}_b\n',
        ]

        code.append(builders[i % len(builders)])
        code.append(f"{sqli_sinks[i % len(sqli_sinks)]}({q})\n")

    # ============================================================
    # 2. Command Injection: 100 variants
    # ============================================================

    cmd_sinks = [
        "os.system",
        "os.popen",
        "subprocess.run",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "os.execv",
        "os.execve",
        "os.spawnv",
        "pty.spawn",
        "run_command",
        "execute_command",
        "exec_command",
        "shell",
        "run_shell",
        "execute_shell",
        "system",
    ]

    for i in range(100):
        code.append(make_tainted_value("cmd", i))
        src = f"cmd_src_{i}"
        cmd = f"cmd_payload_{i}"

        shapes = [
            f"{cmd} = {src}\n",
            f'{cmd} = "ping " + {src}\n',
            f'{cmd} = f"cat {{{src}}}"\n',
            f"{cmd} = 'ls {{}}'.format({src})\n",
            f'{cmd} = "grep %s" % {src}\n',
        ]

        code.append(shapes[i % len(shapes)])
        code.append(f"{cmd_sinks[i % len(cmd_sinks)]}({cmd})\n")

    # ============================================================
    # 3. Path Traversal: 100 variants
    # ============================================================

    path_sinks = [
        "open",
        "os.open",
        "os.remove",
        "os.unlink",
        "os.rename",
        "os.replace",
        "os.rmdir",
        "os.mkdir",
        "os.makedirs",
        "os.listdir",
        "os.scandir",
        "os.walk",
        "os.stat",
        "shutil.copy",
        "shutil.copyfile",
        "shutil.move",
        "shutil.rmtree",
        "send_file",
        "send_from_directory",
        "Path.read_text",
    ]

    for i in range(100):
        code.append(make_tainted_value("path", i))
        src = f"path_src_{i}"
        p = f"path_payload_{i}"

        shapes = [
            f"{p} = {src}\n",
            f'{p} = "/var/www/" + {src}\n',
            f'{p} = f"/tmp/{{{src}}}"\n',
            f"""{p} = "uploads/{{}}".format({src})\n"""
,
            f'{p} = "../" + {src}\n',
        ]

        code.append(shapes[i % len(shapes)])
        code.append(f"{path_sinks[i % len(path_sinks)]}({p})\n")

    # ============================================================
    # 4. XSS: 100 variants
    # ============================================================

    xss_sinks = [
        "return_html",
        "Response",
        "make_response",
        "HttpResponse",
        "HTMLResponse",
        "render_template_string",
        "Template",
        "Markup",
        "mark_safe",
        "self.write",
        "web.Response",
        "template",
        "script_context",
        "href_attribute",
        "src_attribute",
        "onclick_attribute",
        "onload_attribute",
        "onerror_attribute",
        "rich_text_render",
        "markdown_to_html",
    ]

    for i in range(100):
        code.append(make_tainted_value("xss", i))
        src = f"xss_src_{i}"
        html = f"xss_html_{i}"

        shapes = [
            f'{html} = "<p>" + {src} + "</p>"\n',
            f'{html} = f"<h1>{{{src}}}</h1>"\n',
f"""{html} = "<div>{{}}</div>".format({src})\n"""
            f'{html} = "<span>%s</span>" % {src}\n',
            f'{html}_a = {src}\n{html} = "<script>" + {html}_a + "</script>"\n',
        ]

        code.append(shapes[i % len(shapes)])
        code.append(f"{xss_sinks[i % len(xss_sinks)]}({html})\n")

    # ============================================================
    # 5. Insecure Deserialization: 100 variants
    # ============================================================

    deser_sinks = [
        "pickle.loads",
        "pickle.load",
        "_pickle.loads",
        "_pickle.load",
        "dill.loads",
        "dill.load",
        "cloudpickle.loads",
        "cloudpickle.load",
        "joblib.load",
        "torch.load",
        "numpy.load",
        "pandas.read_pickle",
        "yaml.load",
        "marshal.loads",
        "marshal.load",
        "deserialize",
        "unsafe_deserialize",
        "load_object",
        "loads_object",
        "restore_object",
    ]

    for i in range(100):
        code.append(make_tainted_value("deser", i))
        src = f"deser_src_{i}"
        payload = f"deser_payload_{i}"

        shapes = [
            f"{payload} = {src}\n",
            f"{payload}_a = {src}\n{payload} = {payload}_a\n",
            f"{payload} = base64.b64decode({src})\n",
            f"{payload} = binascii.unhexlify({src})\n",
            f"{payload}_a = {src}\n{payload}_b = {payload}_a\n{payload} = {payload}_b\n",
        ]

        code.append(shapes[i % len(shapes)])
        code.append(f"{deser_sinks[i % len(deser_sinks)]}({payload})\n")

    # ============================================================
    # 6. Hardcoded Secrets: 100 variants
    # ============================================================

    secret_names = [
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
        "aws_secret_access_key",
        "jwt_secret",
    ]

    secret_values = [
        "admin123",
        "hunter2",
        "password123",
        "supersecret",
        "django-insecure-hardcoded-secret",
        "flask-secret-key",
        "sk_test_123456",
        "AIzaGoogleKey",
        "AKIAEXAMPLE",
        "ghp_hardcodedgithubtoken",
        "xoxb-hardcoded-slack-bot-token",
        "refresh-token-hardcoded",
        "-----BEGIN PRIVATE KEY-----",
        "client-secret-hardcoded",
        "consumer-secret-hardcoded",
        "postgres://admin:password@localhost/db",
        "dbpass-hardcoded",
        "smtppass-hardcoded",
        "aws-secret-hardcoded",
        "jwt-secret-hardcoded",
    ]

    for i in range(100):
        name = secret_names[i % len(secret_names)]
        value = secret_values[i % len(secret_values)]
        code.append(f'{name} = "{value}_{i}"\n')

    # ============================================================
    # 7. Weak Cryptography: 100 variants
    # ============================================================

    crypto_sinks = [
        "hashlib.md5",
        "hashlib.sha1",
        "Crypto.Hash.MD5.new",
        "Crypto.Hash.SHA1.new",
        "Crypto.Cipher.DES.new",
        "Crypto.Cipher.ARC2.new",
        "Crypto.Cipher.ARC4.new",
        "Crypto.Cipher.Blowfish.new",
        "cryptography.hazmat.primitives.ciphers.algorithms.ARC4",
        "cryptography.hazmat.primitives.ciphers.algorithms.Blowfish",
        "cryptography.hazmat.primitives.ciphers.algorithms.TripleDES",
        "modes.ECB",
        "hashlib.sha256",
        "hashlib.sha512",
        "hashlib.pbkdf2_hmac",
        "encrypt",
        "decrypt",
        "hash_password",
        "make_hash",
        "cryptography.hazmat.primitives.hashes.MD5",
    ]

    for i in range(100):
        code.append(make_tainted_value("crypto", i))
        src = f"crypto_src_{i}"
        code.append(f"crypto_result_{i} = {crypto_sinks[i % len(crypto_sinks)]}({src})\n")

    # ============================================================
    # 8. Insecure Random: 100 variants
    # ============================================================

    random_sinks = [
        "random.random",
        "random.randint",
        "random.randrange",
        "random.choice",
        "random.choices",
        "random.sample",
        "random.uniform",
        "random.getrandbits",
        "random.randbytes",
        "random.Random",
        "numpy.random.random",
        "numpy.random.randint",
        "numpy.random.choice",
        "numpy.random.bytes",
        "np.random.random",
        "np.random.randint",
        "np.random.choice",
        "np.random.bytes",
        "uuid.uuid1",
        "time.time",
    ]

    random_args = [
        "",
        "1, 9999",
        "1, 9999",
        '["a", "b", "c"]',
        '["a", "b", "c"]',
        '["a", "b", "c"], 2',
        "1, 100",
        "64",
        "16",
        "",
        "",
        "1, 9999",
        '["a", "b", "c"]',
        "16",
        "",
        "1, 9999",
        '["a", "b", "c"]',
        "16",
        "",
        "",
    ]

    for i in range(100):
        sink = random_sinks[i % len(random_sinks)]
        args = random_args[i % len(random_args)]
        code.append(f"token_{i} = {sink}({args})\n")

    # ============================================================
    # 9. SSRF: 100 variants
    # ============================================================

    ssrf_sinks = [
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "requests.head",
        "requests.options",
        "requests.request",
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "httpx.patch",
        "httpx.delete",
        "httpx.request",
        "urllib.request.urlopen",
        "urllib.request.Request",
        "urllib3.request",
        "socket.create_connection",
        "socket.connect",
        "aiohttp.ClientSession.get",
    ]

    for i in range(100):
        code.append(make_tainted_value("ssrf", i))
        src = f"ssrf_src_{i}"
        url = f"ssrf_url_{i}"

        shapes = [
            f"{url} = {src}\n",
            f'{url} = "http://" + {src}\n',
            f'{url} = f"http://{{{src}}}"\n',
f"""{url} = "http://{{}}".format({src})\n"""
            f"{url}_a = {src}\n{url} = {url}_a\n",
        ]

        code.append(shapes[i % len(shapes)])
        code.append(f"{ssrf_sinks[i % len(ssrf_sinks)]}({url})\n")

    # ============================================================
    # 10. XXE: 100 variants
    # ============================================================

    xxe_sinks = [
        "xml.etree.ElementTree.fromstring",
        "xml.etree.ElementTree.parse",
        "xml.etree.ElementTree.XML",
        "ElementTree.fromstring",
        "ElementTree.parse",
        "ET.fromstring",
        "ET.parse",
        "ET.XML",
        "xml.dom.minidom.parseString",
        "xml.dom.minidom.parse",
        "xml.sax.parseString",
        "xml.sax.parse",
        "lxml.etree.fromstring",
        "lxml.etree.parse",
        "lxml.etree.XML",
        "xml.dom.pulldom.parseString",
        "xml.dom.pulldom.parse",
        "parse_xml",
        "load_xml",
        "xml_parse",
    ]

    for i in range(100):
        code.append(make_tainted_value("xxe", i))
        src = f"xxe_src_{i}"
        xml_payload = f"xxe_payload_{i}"

        shapes = [
            f"{xml_payload} = {src}\n",
            f"{xml_payload}_a = {src}\n{xml_payload} = {xml_payload}_a\n",
            f'{xml_payload} = "<root>" + {src} + "</root>"\n',
            f'{xml_payload} = f"<root>{{{src}}}</root>"\n',
f"""{xml_payload} = "<root>{{}}</root>".format({src})\n"""
        ]

        code.append(shapes[i % len(shapes)])
        code.append(f"{xxe_sinks[i % len(xxe_sinks)]}({xml_payload})\n")

    return "\n".join(code)


def build_analysis(test_code):
    tree = ast.parse(test_code)

    builder = Builder()
    cfg = builder.cfgBuild(tree.body)

    rda = ReachingDefinitionAnalyzer()

    for block in cfg.blocks:
        rda.defCollect(block)

    for block in cfg.blocks:
        rda.defHandle(block)

    rda.transferFunction(cfg)

    uda = UseDefAnalyzer()
    uda.analyze(cfg, rda)

    return cfg, rda, uda


def count_unique_findings(output):
    findings = set()

    for line in output.splitlines():
        line = line.strip()

        if line.startswith("Sink Statement:"):
            findings.add(line)

        elif line.startswith("Offending Statement:"):
            findings.add(line)

        elif line.startswith("Offending Assignment:"):
            findings.add(line)

    return len(findings)


def run_1000_variant_test():
    test_code = make_test_code()
    cfg, rda, uda = build_analysis(test_code)

    print("\n========== RUNNING 1000-CASE VARIANT STRESS TEST ==========\n")

    total_expected = 0
    total_found = 0

    for rule in ALL_RULES:
        taint_analyzer = TaintAnalyzer(uda, rda)

        buffer = io.StringIO()

        with contextlib.redirect_stdout(buffer):
            if rule.detectionType == "taintFlow":
                taint_analyzer.flowRun(cfg, rule)
            elif rule.detectionType == "patternBased":
                taint_analyzer.patternRun(cfg, rule)

        output = buffer.getvalue()
        found_count = count_unique_findings(output)
        expected_count = EXPECTED_PER_RULE.get(rule.name, 100)

        total_expected += expected_count
        total_found += found_count

        status = "PASS" if found_count == expected_count else "FAIL"
        print(f"{rule.name}: {found_count}/{expected_count} individual findings detected [{status}]")

    print("\n========== FINAL 1000-CASE SUMMARY ==========")
    print(f"Total findings detected: {total_found}/{total_expected}")

    if total_found == total_expected:
        print("FULL PASS: vulnAI caught all 1000 variant test cases.")
    else:
        print("PARTIAL PASS: Some variant cases were missed.")


if __name__ == "__main__":
    run_1000_variant_test()