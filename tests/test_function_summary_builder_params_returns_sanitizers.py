from __future__ import annotations

import pytest

from .conftest import build_summary


def test_direct_source_return_records_unconditional_return_cwes(registry, CfgBuilderClass):
    summary, *_ = build_summary(
        """
        def target():
            return input()
        """,
        "target",
        registry,
        CfgBuilderClass,
    )
    assert summary.returnsTainted["CWE-78"] is True
    assert summary.returnsTainted["CWE-89"] is True
    assert summary.returnsTainted["CWE-79"] is True
    assert summary.directSourceReturn["CWE-78"] == "input"


def test_indirect_source_return_through_assignments_records_unconditional_return(registry, CfgBuilderClass):
    summary, *_ = build_summary(
        """
        def target():
            x = input()
            y = x
            z = y
            return z
        """,
        "target",
        registry,
        CfgBuilderClass,
    )
    assert summary.returnsTainted["CWE-78"] is True
    assert summary.returnsTainted["CWE-89"] is True
    assert summary.returnsTainted["CWE-79"] is True


def test_parameter_to_return_dependency_is_recorded(registry, CfgBuilderClass):
    summary, *_ = build_summary(
        """
        def target(user):
            cleanish = user
            return cleanish
        """,
        "target",
        registry,
        CfgBuilderClass,
    )
    assert "user" in summary.taintedReturnParams
    assert summary.taintedReturnParams["user"] >= {"CWE-78", "CWE-89", "CWE-79", "CWE-22", "CWE-502", "CWE-611"}


def test_parameter_to_sink_bridge_is_recorded_for_command_injection(registry, CfgBuilderClass):
    summary, *_ = build_summary(
        """
        def target(cmd):
            os.system(cmd)
        """,
        "target",
        registry,
        CfgBuilderClass,
    )
    assert summary.paramsToSinks["cmd"]["CWE-78"] == ["os.system"]
    assert "os.system" in summary.sinkCalls
    assert summary.localVulnerabilities == [], "Param-to-sink bridge is conditional, not a local source-to-sink bug."


@pytest.mark.parametrize(
    "code,param,cwe,sink",
    [
        ("""def target(cmd):\n    os.system(cmd)\n""", "cmd", "CWE-78", "os.system"),
        ("""def target(query):\n    cursor.execute(query)\n""", "query", "CWE-89", "cursor.execute"),
        ("""def target(html):\n    render_template_string(html)\n""", "html", "CWE-79", "render_template_string"),
        ("""def target(path):\n    open(path)\n""", "path", "CWE-22", "open"),
        ("""def target(blob):\n    pickle.loads(blob)\n""", "blob", "CWE-502", "pickle.loads"),
        ("""def target(xml):\n    ET.fromstring(xml)\n""", "xml", "CWE-611", "ET.fromstring"),
    ],
)
def test_parameter_to_sink_bridges_for_each_taint_vulnerability(code, param, cwe, sink, registry, CfgBuilderClass):
    summary, *_ = build_summary(code, "target", registry, CfgBuilderClass)
    assert sink in summary.paramsToSinks[param][cwe]


def test_sanitizer_removes_only_matching_label_from_return(registry, CfgBuilderClass):
    summary, *_ = build_summary(
        """
        def target(user):
            safe_html = html.escape(user)
            return safe_html
        """,
        "target",
        registry,
        CfgBuilderClass,
    )
    assert "user" in summary.taintedReturnParams
    assert "CWE-79" not in summary.taintedReturnParams["user"], "html.escape should remove XSS only."
    assert "CWE-89" in summary.taintedReturnParams["user"], "html.escape should not remove SQLi."
    assert "CWE-78" in summary.taintedReturnParams["user"], "html.escape should not remove command injection."


def test_sanitizer_subtraction_is_local_to_its_subtree_not_whole_expression(registry, CfgBuilderClass):
    summary, *_ = build_summary(
        """
        def target(cleaned, still_dirty):
            combined = html.escape(cleaned) + still_dirty
            return combined
        """,
        "target",
        registry,
        CfgBuilderClass,
    )
    assert "cleaned" in summary.taintedReturnParams
    assert "still_dirty" in summary.taintedReturnParams
    assert "CWE-79" not in summary.taintedReturnParams["cleaned"]
    assert "CWE-79" in summary.taintedReturnParams["still_dirty"]


def test_keyword_argument_to_sink_is_checked_inside_intraprocedural_sink_scan(registry, CfgBuilderClass):
    summary, *_ = build_summary(
        """
        def target(cmd):
            subprocess.run(args=cmd)
        """,
        "target",
        registry,
        CfgBuilderClass,
    )
    assert "subprocess.run" in summary.paramsToSinks["cmd"]["CWE-78"]


def test_method_receiver_dependency_is_preserved_for_method_calls(registry, CfgBuilderClass):
    summary, *_ = build_summary(
        """
        def target(cmd):
            cleaned = cmd.strip()
            os.system(cleaned)
        """,
        "target",
        registry,
        CfgBuilderClass,
    )
    assert "os.system" in summary.paramsToSinks["cmd"]["CWE-78"]


def test_branch_with_one_tainted_and_one_safe_definition_still_reports_possible_return_taint(registry, CfgBuilderClass):
    summary, *_ = build_summary(
        """
        def target(cond):
            if cond:
                x = input()
            else:
                x = "safe"
            return x
        """,
        "target",
        registry,
        CfgBuilderClass,
    )
    assert summary.returnsTainted["CWE-78"] is True


def test_loop_propagation_preserves_taint_through_augassign(registry, CfgBuilderClass):
    summary, *_ = build_summary(
        """
        def target():
            x = input()
            for item in ["a", "b"]:
                x += item
            os.system(x)
        """,
        "target",
        registry,
        CfgBuilderClass,
    )
    assert any(v["cwe"] == "CWE-78" and v["sink"] == "os.system" for v in summary.localVulnerabilities)
