from __future__ import annotations

import ast
from textwrap import dedent

import pytest

from vulnai.analysis.intraprocedural.reachingdef import ReachingDefinitionAnalyzer
from vulnai.analysis.intraprocedural.usedef import UseDefAnalyzer
from vulnai.analysis.interprocedural.summary_and_graph.summary_builder import FunctionSummaryBuilder

from .conftest import all_statements, build_cfg_for_function, get_function, parse_module, run_rda_uda


def test_param_extract_handles_all_python_parameter_kinds():
    func = get_function(
        """
        def target(a, /, b, *args, c, **kwargs):
            pass
        """,
        "target",
    )
    builder = FunctionSummaryBuilder(UseDefAnalyzer(), ReachingDefinitionAnalyzer())
    assert builder.paramExtract(func) == ["a", "b", "c", "args", "kwargs"]


def test_recursive_getter_resolves_simple_and_nested_call_names():
    module = parse_module(
        """
        def target():
            input()
            os.system("ls")
            xml.etree.ElementTree.fromstring("<x/>")
        """
    )
    calls = [node for node in ast.walk(module) if isinstance(node, ast.Call)]
    builder = FunctionSummaryBuilder(UseDefAnalyzer(), ReachingDefinitionAnalyzer())
    names = {builder.getCallName(call) for call in calls}
    assert "input" in names
    assert "os.system" in names
    assert "xml.etree.ElementTree.fromstring" in names


def test_cfg_builder_creates_blocks_edges_arguments_and_return(CfgBuilderClass):
    cfg_obj, _ = build_cfg_for_function(
        """
        def target(x):
            y = "safe"
            if x:
                y = input()
            else:
                y = "still_safe"
            return y
        """,
        "target",
        CfgBuilderClass,
    )
    stmts = all_statements(cfg_obj)
    assert any(isinstance(stmt, ast.arguments) for stmt in stmts), "Function args must be injected into CFG for RDA/UDA."
    assert any(isinstance(stmt, ast.Return) for stmt in stmts)
    assert len(cfg_obj.blocks) >= 5, "if/else should create entry/body/branch/join/exit-style structure."
    assert any(block.prevBlocks for block in cfg_obj.blocks), "CFG should contain connected predecessor edges."


def test_rda_extract_names_unpacks_nested_tuple_and_list_targets():
    rda = ReachingDefinitionAnalyzer()
    stmt = parse_module("(a, [b, c]) = value").body[0]
    assert isinstance(stmt, ast.Assign)
    assert rda.extractNames(stmt.targets[0]) == ["a", "b", "c"]


def test_uda_use_collect_ignores_store_names_and_collects_nested_loads():
    uda = UseDefAnalyzer()
    stmt = parse_module("result = left + obj.method(arg, key=kw)").body[0]
    uses = set(uda.useCollect(stmt))
    assert "result" not in uses
    assert {"left", "obj", "arg", "kw"}.issubset(uses)


def test_uda_definition_collect_for_assignment_variants():
    uda = UseDefAnalyzer()
    samples = {
        "x = y": ["x"],
        "a, b = pair": ["a", "b"],
        "x += 1": ["x"],
        "x: int = 1": ["x"],
    }
    for code, expected in samples.items():
        stmt = parse_module(code).body[0]
        assert uda.definitionCollect(stmt) == expected


@pytest.mark.current_limitation
@pytest.mark.xfail(reason="Current RDA/UDA uses ast.arguments.var instead of ast.arguments.vararg in pasted code.")
def test_rda_uda_argument_collection_supports_vararg_and_kwarg_without_crashing():
    func = get_function("""def target(a, *args, **kwargs):\n    return a\n""", "target")
    args = func.args
    rda = ReachingDefinitionAnalyzer()
    uda = UseDefAnalyzer()
    # Desired behavior: these should not raise, and should include args/kwargs.
    assert rda.extractNames(ast.Name(id="x", ctx=ast.Store())) == ["x"]
    assert set(uda.definitionCollect(args)) == {"a", "args", "kwargs"}


def test_rda_and_uda_connect_use_to_single_reaching_definition(CfgBuilderClass):
    cfg_obj, _ = build_cfg_for_function(
        """
        def target():
            x = input()
            y = x
            return y
        """,
        "target",
        CfgBuilderClass,
    )
    rda, uda = run_rda_uda(cfg_obj)
    assign_y = next(stmt for stmt in all_statements(cfg_obj) if isinstance(stmt, ast.Assign) and ast.unparse(stmt.targets[0]) == "y")
    incoming = uda.useDefEdges[assign_y]["x"]
    assert len(incoming) == 1
    only_def = next(iter(incoming))
    assert only_def.var == "x"
    assert ast.unparse(only_def.node).strip() == "x = input()"


def test_rda_and_uda_preserve_multiple_reaching_defs_across_if_else(CfgBuilderClass):
    cfg_obj, _ = build_cfg_for_function(
        """
        def target(cond):
            if cond:
                x = input()
            else:
                x = "safe"
            y = x
            return y
        """,
        "target",
        CfgBuilderClass,
    )
    rda, uda = run_rda_uda(cfg_obj)
    assign_y = next(stmt for stmt in all_statements(cfg_obj) if isinstance(stmt, ast.Assign) and ast.unparse(stmt.targets[0]) == "y")
    incoming = uda.useDefEdges[assign_y]["x"]
    source_lines = {ast.unparse(defn.node).strip() for defn in incoming}
    assert "x = input()" in source_lines
    assert "x = 'safe'" in source_lines or 'x = "safe"' in source_lines
    assert len(incoming) == 2
