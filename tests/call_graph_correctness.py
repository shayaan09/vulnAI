import pytest
import ast
from vulnai.analysis.interprocedural.code_graph.graph import CodeGraph
from vulnai.analysis.interprocedural.code_graph.callgraphbuild import CallGraphBuilder
from vulnai.analysis.interprocedural.structured_storage.codebase_index import CodebaseIndex, ModuleInfo, FunctionInfo

# =====================================================================
# PROPER TEST HARNESS (No Hacks, No Bypasses)
# =====================================================================

class MockCodebaseIndex(CodebaseIndex):
    def __init__(self):
        self._mock_modules = {}
        self._mock_function_table = {}
        self._mock_builtins = {"print", "len", "range", "str", "int"}
    
    @property
    def modules(self): return self._mock_modules
    @property
    def functionTable(self): return self._mock_function_table
    @property
    def builtins(self): return self._mock_builtins

def analyze_code(app_source: str, db_source: str = None):
    """
    Simulates the real AST extraction pipeline.
    Parses code, registers FunctionInfo correctly, and initializes graph nodes BEFORE building edges.
    """
    index = MockCodebaseIndex()
    graph = CodeGraph()
    
    # 1. Setup DB Module (if provided)
    if db_source:
        db_mod = ModuleInfo(filePath="db.py", moduleName="db", astTree=ast.parse(db_source), parseError=None)
        db_mod.imports = []
        for node in db_mod.astTree.body:
            if isinstance(node, ast.FunctionDef):
                global_id = f"function:db.{node.name}"
                func_info = FunctionInfo(
                    name=node.name, 
                    globalName=f"db.{node.name}", 
                    moduleName="db", 
                    node=node, 
                    params=[a.arg for a in node.args.args], 
                    lineno=node.lineno,
                    endLineno=getattr(node, "end_lineno", node.lineno),
                    decorators=[],
                    isAsync=False
                )
                db_mod.functions[node.name] = func_info
                index.functionTable[func_info.globalName] = func_info
                # Register proper graph node
                graph.nodes[global_id] = type("MockNode", (), {"id": global_id})()
                graph.outgoing[global_id] = []
                graph.incoming[global_id] = []
        index.modules["db"] = db_mod

    # 2. Setup App Module
    app_mod = ModuleInfo(filePath="app.py", moduleName="app", astTree=ast.parse(app_source), parseError=None)
    
    # Simple import parser for the mock
    app_mod.imports = []
    for node in app_mod.astTree.body:
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                app_mod.imports.append(type("MockImp", (), {"moduleName": node.module, "importedName": alias.name, "alias": alias.asname, "kind": "from_import"})())
        elif isinstance(node, ast.Import):
            for alias in node.names:
                app_mod.imports.append(type("MockImp", (), {"moduleName": alias.name, "importedName": alias.name, "alias": alias.asname, "kind": "import"})())

    for node in app_mod.astTree.body:
        if isinstance(node, ast.FunctionDef):
            global_id = f"function:app.{node.name}"
            func_info = FunctionInfo(
                name=node.name, 
                globalName=f"app.{node.name}", 
                moduleName="app", 
                node=node, 
                params=[a.arg for a in node.args.args], 
                lineno=node.lineno,
                endLineno=getattr(node, "end_lineno", node.lineno),
                decorators=[],
                isAsync=False
            )
            app_mod.functions[node.name] = func_info
            index.functionTable[func_info.globalName] = func_info
            # Register proper graph node
            graph.nodes[global_id] = type("MockNode", (), {"id": global_id})()
            graph.outgoing[global_id] = []
            graph.incoming[global_id] = []
    
    index.modules["app"] = app_mod

    # 3. Build Edges
    builder = CallGraphBuilder(index)
    builder.resolver.builtins = index.builtins
    builder.build(graph)
    
    return graph

# =====================================================================
# ATOMIC CORRECTNESS TESTS
# =====================================================================

def test_local_function_call():
    src = """
def helper(): pass
def main():
    helper()
"""
    graph = analyze_code(src)
    assert len(graph.edges) == 1, "Should find exactly 1 edge."
    edge = graph.edges[0]
    assert edge.source == "function:app.main"
    assert edge.target == "function:app.helper"

def test_from_import_call():
    db_src = "def run_query(): pass"
    app_src = """
from db import run_query
def main():
    run_query()
"""
    graph = analyze_code(app_src, db_src)
    assert len(graph.edges) == 1
    edge = graph.edges[0]
    assert edge.source == "function:app.main"
    assert edge.target == "function:db.run_query"

def test_module_attribute_call():
    db_src = "def run_query(): pass"
    app_src = """
import db
def main():
    db.run_query()
"""
    graph = analyze_code(app_src, db_src)
    assert len(graph.edges) == 1
    edge = graph.edges[0]
    assert edge.source == "function:app.main"
    assert edge.target == "function:db.run_query"

def test_alias_import_call():
    db_src = "def run_query(): pass"
    app_src = """
import db as database
def main():
    database.run_query()
"""
    graph = analyze_code(app_src, db_src)
    assert len(graph.edges) == 1
    edge = graph.edges[0]
    assert edge.source == "function:app.main"
    assert edge.target == "function:db.run_query"

def test_parameter_shadowing_blocks_edge():
    db_src = "def run_query(): pass"
    app_src = """
from db import run_query
def main(run_query):
    # This run_query is a local parameter, NOT the global import!
    run_query("Select *")
"""
    graph = analyze_code(app_src, db_src)
    # The analyzer should realize `run_query` is a parameter and NOT connect it to `db.run_query`
    assert len(graph.edges) == 0, "Failed: Analyzer mapped a shadowed parameter to a global function."

def test_builtin_blocks_edge():
    app_src = """
def print_data(): pass
def main():
    print("Hello World") # Builtin 'print', not 'print_data' or unknown global
"""
    graph = analyze_code(app_src)
    assert len(graph.edges) == 0, "Failed: Analyzer mapped a built-in to an internal codebase node."

def test_external_library_blocks_edge():
    app_src = """
import requests
def main():
    requests.get("http://evil.com")
"""
    graph = analyze_code(app_src)
    # 'requests' is not in our MockCodebaseIndex, so it should be left unresolved/dropped
    assert len(graph.edges) == 0, "Failed: Analyzer hallucinated an edge to an external/un-indexed library."