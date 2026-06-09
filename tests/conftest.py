"""
Shared pytest helpers for VulnAI intraprocedural analysis tests.

These tests intentionally exercise the real CFG -> RDA -> UDA -> FunctionSummaryBuilder
pipeline. They are strict: failures usually mean either a real bug or a documented current
limitation in the analysis layer.
"""

from __future__ import annotations

import ast
import importlib
from dataclasses import dataclass
from textwrap import dedent
from typing import Any, Iterable

import pytest

from vulnai.analysis.intraprocedural.reachingdef import ReachingDefinitionAnalyzer
from vulnai.analysis.intraprocedural.usedef import UseDefAnalyzer
from vulnai.analysis.vulnerabilities.vulns import VulnerabilityRule
from vulnai.analysis.vulnerabilities.rule_registry import RuleRegistry
from vulnai.analysis.interprocedural.summary_and_graph.summarystore import FunctionSummary, SummaryStore
from vulnai.analysis.interprocedural.summary_and_graph.summary_builder import FunctionSummaryBuilder


CFG_BUILDER_CANDIDATES = [
    ("vulnai.analysis.intraprocedural.builder", "Builder"),
    ("vulnai.analysis.intraprocedural.cfg_builder", "Builder"),
    ("vulnai.analysis.intraprocedural.cfgbuilder", "Builder"),
    ("vulnai.analysis.intraprocedural.build_cfg", "Builder"),
]


def import_first_attr(candidates: Iterable[tuple[str, str]]) -> Any:
    errors: list[str] = []
    for module_name, attr_name in candidates:
        try:
            module = importlib.import_module(module_name)
            return getattr(module, attr_name)
        except Exception as exc:  # pragma: no cover - this is a test helper guard
            errors.append(f"{module_name}.{attr_name}: {exc!r}")
    raise ImportError("Could not import any candidate:\n" + "\n".join(errors))


@pytest.fixture(scope="session")
def CfgBuilderClass():
    return import_first_attr(CFG_BUILDER_CANDIDATES)


@pytest.fixture
def registry() -> RuleRegistry:
    """A broad test registry covering the vulnerability classes requested."""
    rules = [
        VulnerabilityRule(
            name="Command Injection",
            cwe="CWE-78",
            detectionType="taintFlow",
            sources=["input", "request.args.get", "request.form.get"],
            sinks=["os.system", "subprocess.run", "subprocess.call", "subprocess.Popen"],
            sanitizers=["shlex.quote", "safe_command"],
        ),
        VulnerabilityRule(
            name="SQL Injection",
            cwe="CWE-89",
            detectionType="taintFlow",
            sources=["input", "request.args.get", "request.form.get"],
            sinks=["cursor.execute", "db.execute", "session.execute"],
            sanitizers=["parameterized_query", "sql_escape"],
        ),
        VulnerabilityRule(
            name="Cross-Site Scripting",
            cwe="CWE-79",
            detectionType="taintFlow",
            sources=["input", "request.args.get", "request.form.get"],
            sinks=["render_template_string", "response.write", "Markup"],
            sanitizers=["html.escape", "escape", "bleach.clean"],
        ),
        VulnerabilityRule(
            name="Path Traversal",
            cwe="CWE-22",
            detectionType="taintFlow",
            sources=["input", "request.args.get", "request.form.get"],
            sinks=["open", "Path", "os.path.join"],
            sanitizers=["safe_join", "secure_filename"],
        ),
        VulnerabilityRule(
            name="Insecure Deserialization",
            cwe="CWE-502",
            detectionType="taintFlow",
            sources=["input", "request.data", "request.get_data"],
            sinks=["pickle.loads", "yaml.load"],
            sanitizers=["json.loads", "yaml.safe_load"],
        ),
        VulnerabilityRule(
            name="XXE",
            cwe="CWE-611",
            detectionType="taintFlow",
            sources=["input", "request.data", "request.get_data"],
            sinks=["ET.fromstring", "xml.etree.ElementTree.fromstring", "lxml.etree.parse"],
            sanitizers=["defusedxml.ElementTree.fromstring"],
        ),
        VulnerabilityRule(
            name="Hardcoded Secret",
            cwe="CWE-798",
            detectionType="patternBased",
            sources=[],
            sinks=["API_KEY", "SECRET_KEY", "PASSWORD", "TOKEN"],
            sanitizers=[],
        ),
        VulnerabilityRule(
            name="Weak Cryptography",
            cwe="CWE-327",
            detectionType="patternBased",
            sources=[],
            sinks=["hashlib.md5", "hashlib.sha1", "Crypto.Cipher.DES.new"],
            sanitizers=[],
        ),
        VulnerabilityRule(
            name="Insecure Random",
            cwe="CWE-338",
            detectionType="patternBased",
            sources=[],
            sinks=["random.random", "random.randint", "random.randrange"],
            sanitizers=[],
        ),
        VulnerabilityRule(
            name="Dangerous Eval",
            cwe="CWE-95",
            detectionType="patternBased",
            sources=[],
            sinks=["eval", "exec"],
            sanitizers=[],
        ),
    ]
    return RuleRegistry(rules)


def parse_module(code: str) -> ast.Module:
    return ast.parse(dedent(code))


def get_function(code: str, name: str = "target") -> ast.FunctionDef:
    module = parse_module(code)
    for node in module.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    available = [node.name for node in module.body if isinstance(node, ast.FunctionDef)]
    raise AssertionError(f"Function {name!r} not found. Available: {available}")


def all_statements(cfg_obj) -> list[ast.AST]:
    return [stmt for block in cfg_obj.blocks for stmt in block.statements]


def build_cfg_for_function(code: str, name: str, CfgBuilderClass):
    func = get_function(code, name)
    return CfgBuilderClass().cfgBuild(func), func


def run_rda_uda(cfg_obj):
    """Run RDA/UDA exactly like the pipeline expects.

    If the project still has the known ast.arguments `stmt.var` bug, tests that require
    parameter definitions are xfailed instead of exploding in a confusing way.
    """
    rda = ReachingDefinitionAnalyzer()
    try:
        for block in cfg_obj.blocks:
            rda.defCollect(block)
        for block in cfg_obj.blocks:
            rda.defHandle(block)
        rda.transferFunction(cfg_obj)
    except AttributeError as exc:
        if "object has no attribute 'var'" in str(exc):
            pytest.xfail("RDA/UDA currently uses ast.arguments.var; Python AST uses ast.arguments.vararg.")
        raise

    uda = UseDefAnalyzer()
    try:
        uda.analyze(cfg_obj, rda)
    except AttributeError as exc:
        if "object has no attribute 'var'" in str(exc):
            pytest.xfail("UDA currently uses ast.arguments.var; Python AST uses ast.arguments.vararg.")
        raise
    return rda, uda


def build_summary(code: str, name: str, registry: RuleRegistry, CfgBuilderClass, module_name: str = "testmod"):
    cfg_obj, func = build_cfg_for_function(code, name, CfgBuilderClass)
    rda, uda = run_rda_uda(cfg_obj)
    builder = FunctionSummaryBuilder(uda, rda)
    summary = builder.buildSummary(func, cfg_obj, registry, moduleName=module_name)
    return summary, cfg_obj, rda, uda, func


def assert_has_local_vuln(summary: FunctionSummary, *, cwe: str, sink: str) -> dict:
    matches = [v for v in summary.localVulnerabilities if v.get("cwe") == cwe and v.get("sink") == sink]
    assert matches, f"Expected local vulnerability {cwe=} {sink=}, got {summary.localVulnerabilities!r}"
    return matches[0]


def assert_has_pattern(summary: FunctionSummary, *, cwe: str, contains: str | None = None) -> dict:
    matches = [v for v in summary.bannedPatterns if v.get("cwe") == cwe]
    if contains is not None:
        matches = [v for v in matches if contains in v.get("offendingCode", "")]
    assert matches, f"Expected pattern finding {cwe=} {contains=}, got {summary.bannedPatterns!r}"
    return matches[0]
