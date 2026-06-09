from __future__ import annotations

import pytest

from .conftest import assert_has_local_vuln, assert_has_pattern, build_summary


@pytest.mark.parametrize(
    "code,cwe,sink",
    [
        ("""def target():\n    os.system(input())\n""", "CWE-78", "os.system"),
        ("""def target():\n    subprocess.run(input())\n""", "CWE-78", "subprocess.run"),
        ("""def target():\n    cursor.execute(input())\n""", "CWE-89", "cursor.execute"),
        ("""def target():\n    render_template_string(input())\n""", "CWE-79", "render_template_string"),
        ("""def target():\n    response.write(input())\n""", "CWE-79", "response.write"),
        ("""def target():\n    open(input())\n""", "CWE-22", "open"),
        ("""def target():\n    pickle.loads(input())\n""", "CWE-502", "pickle.loads"),
        ("""def target():\n    yaml.load(input())\n""", "CWE-502", "yaml.load"),
        ("""def target():\n    ET.fromstring(input())\n""", "CWE-611", "ET.fromstring"),
        ("""def target():\n    xml.etree.ElementTree.fromstring(input())\n""", "CWE-611", "xml.etree.ElementTree.fromstring"),
    ],
)
def test_direct_source_to_sink_local_vulnerabilities_for_all_taint_rules(code, cwe, sink, registry, CfgBuilderClass):
    summary, *_ = build_summary(code, "target", registry, CfgBuilderClass)
    assert_has_local_vuln(summary, cwe=cwe, sink=sink)


@pytest.mark.parametrize(
    "code,cwe,contains",
    [
        ("""def target():\n    eval("1 + 1")\n""", "CWE-95", "eval"),
        ("""def target():\n    exec("x = 1")\n""", "CWE-95", "exec"),
        ("""def target():\n    random.random()\n""", "CWE-338", "random.random"),
        ("""def target():\n    random.randint(1, 10)\n""", "CWE-338", "random.randint"),
        ("""def target():\n    hashlib.md5(b"abc")\n""", "CWE-327", "hashlib.md5"),
        ("""def target():\n    hashlib.sha1(b"abc")\n""", "CWE-327", "hashlib.sha1"),
    ],
)
def test_pattern_based_banned_call_findings(code, cwe, contains, registry, CfgBuilderClass):
    summary, *_ = build_summary(code, "target", registry, CfgBuilderClass)
    assert_has_pattern(summary, cwe=cwe, contains=contains)


@pytest.mark.parametrize(
    "code,varname",
    [
        ("""def target():\n    API_KEY = "abc123"\n""", "API_KEY"),
        ("""def target():\n    SECRET_KEY = "secret"\n""", "SECRET_KEY"),
        ("""def target():\n    PASSWORD = "password"\n""", "PASSWORD"),
        ("""def target():\n    settings.TOKEN = "token"\n""", "TOKEN"),
    ],
)
def test_pattern_based_hardcoded_secret_assignments_are_detected(code, varname, registry, CfgBuilderClass):
    summary, *_ = build_summary(code, "target", registry, CfgBuilderClass)
    assert_has_pattern(summary, cwe="CWE-798", contains=varname)


@pytest.mark.current_limitation
@pytest.mark.xfail(reason="Current checkPatternBased appends all pattern rules after one secret-var match; it should only append matched rules.")
def test_hardcoded_secret_does_not_report_unrelated_pattern_rules(registry, CfgBuilderClass):
    summary, *_ = build_summary(
        """
        def target():
            API_KEY = "abc123"
        """,
        "target",
        registry,
        CfgBuilderClass,
    )
    cwes = {finding["cwe"] for finding in summary.bannedPatterns}
    assert cwes == {"CWE-798"}


def test_safe_literals_do_not_create_local_taint_findings(registry, CfgBuilderClass):
    summary, *_ = build_summary(
        """
        def target():
            os.system("ls")
            cursor.execute("SELECT 1")
            render_template_string("<p>safe</p>")
            open("/tmp/file.txt")
        """,
        "target",
        registry,
        CfgBuilderClass,
    )
    assert summary.localVulnerabilities == []


def test_duplicate_local_vulnerabilities_are_deduped_by_signature(registry, CfgBuilderClass):
    summary, *_ = build_summary(
        """
        def target():
            os.system(input())
            os.system(input())
        """,
        "target",
        registry,
        CfgBuilderClass,
    )
    matches = [v for v in summary.localVulnerabilities if v["cwe"] == "CWE-78" and v["sink"] == "os.system"]
    assert len(matches) == 2, "Two different source-to-sink statements should both be reported."
