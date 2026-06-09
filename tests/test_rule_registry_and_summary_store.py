from vulnai.analysis.interprocedural.summary_and_graph.summarystore import FunctionSummary, SummaryStore


def test_rule_registry_splits_taint_and_pattern_rules(registry):
    assert {r.cwe for r in registry.taintRules} >= {
        "CWE-78", "CWE-89", "CWE-79", "CWE-22", "CWE-502", "CWE-611"
    }
    assert {r.cwe for r in registry.patternRules} >= {"CWE-798", "CWE-327", "CWE-338", "CWE-95"}


def test_rule_registry_source_sink_sanitizer_maps(registry):
    assert registry.getSourceCwes("input") >= {"CWE-78", "CWE-89", "CWE-79", "CWE-22", "CWE-502", "CWE-611"}
    assert registry.getSinkCwes("os.system") == {"CWE-78"}
    assert registry.getSinkCwes("cursor.execute") == {"CWE-89"}
    assert registry.getSinkCwes("render_template_string") == {"CWE-79"}
    assert registry.getSinkCwes("pickle.loads") == {"CWE-502"}
    assert registry.getSinkCwes("ET.fromstring") == {"CWE-611"}
    assert registry.getSanitizerCwes("html.escape") == {"CWE-79"}
    assert registry.getSanitizerCwes("shlex.quote") == {"CWE-78"}
    assert registry.isTrackedAnywhere("input")
    assert not registry.isTrackedAnywhere("totally_unknown_call")


def test_summary_store_roundtrip():
    store = SummaryStore()
    summary = FunctionSummary(functionName="mod.f")
    summary.returnsTainted["CWE-78"] = True
    store.addSummary(summary)
    assert store.getSummary("mod.f") is summary
    assert store.getSummary("mod.missing") is None
