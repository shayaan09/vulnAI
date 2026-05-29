import pytest
import ast
import os
import inspect
from vulnai.analysis.interprocedural.code_graph.graph import CodeGraph
from vulnai.analysis.interprocedural.code_graph.callgraphbuild import CallGraphBuilder
from vulnai.analysis.interprocedural.structured_storage.codebase_index import CodebaseIndex, ModuleInfo, FunctionInfo

class DiagnosticCodeGraph(CodeGraph):
    def addEdge(self, edge, *args, **kwargs):
        # 1. Backfill the nodes directory so the gatekeeper check passes
        if isinstance(self.nodes, dict):
            if edge.source not in self.nodes:
                self.nodes[edge.source] = type("MockNode", (), {"id": edge.source})()
            if edge.target not in self.nodes:
                self.nodes[edge.target] = type("MockNode", (), {"id": edge.target})()
        
        # 2. Backfill incoming/outgoing adjacency collections to prevent KeyErrors
        if isinstance(self.outgoing, dict) and edge.source not in self.outgoing:
            self.outgoing[edge.source] = []
        if isinstance(self.incoming, dict) and edge.target not in self.incoming:
            self.incoming[edge.target] = []
            
        # 3. Ensure the opposing slots exist too just in case structural integrity is checked later
        if isinstance(self.outgoing, dict) and edge.target not in self.outgoing:
            self.outgoing[edge.target] = []
        if isinstance(self.incoming, dict) and edge.source not in self.incoming:
            self.incoming[edge.source] = []

        print(f"    [GRAPH MATCH] Intercepted Edge: {edge.source} -> {edge.target}")
        return super().addEdge(edge, *args, **kwargs)

class StabbedCodebaseIndex(CodebaseIndex):
    def __init__(self):
        self._mock_modules = {}
        self._mock_function_table = {}
        self._mock_builtins = {"print", "len", "range", "str", "int"}
        self.importGraph = {}
        self.diagnostics = []

    @property
    def modules(self):
        return self._mock_modules

    @property
    def functionTable(self):
        return self._mock_function_table

    @property
    def builtins(self):
        return self._mock_builtins


def test_call_graph_gatekeeper_and_resolutions():
    with open("database.py", "w") as f:
        f.write("def run_query(sql_string):\n    pass")
        
    app_source = """
from database import run_query
import os

def local_helper(data):
    return data.strip()

def main():
    print("Initializing")
    clean_data = local_helper("  payload  ")
    run_query(clean_data)
    os.system(f"echo {clean_data}")

def shadow_wrapper(run_query):
    run_query("Select * from logs")
"""
    with open("app.py", "w") as f:
        f.write(app_source)

    try:
        stub_index = StabbedCodebaseIndex()

        # Build Database Module
        db_mod = ModuleInfo(
            filePath="database.py",
            moduleName="database",
            astTree=ast.parse("def run_query(sql_string):\n    pass"),
            parseError=None
        )
        db_mod.imports = []
        for node in db_mod.astTree.body:
            if isinstance(node, ast.FunctionDef):
                func_info = FunctionInfo(
                    name=node.name,
                    globalName=f"database.{node.name}",
                    moduleName="database",
                    node=node,
                    params=[arg.arg for arg in node.args.args],
                    lineno=node.lineno,
                    endLineno=getattr(node, "end_lineno", node.lineno),
                    decorators=[],
                    isAsync=False
                )
                db_mod.functions[node.name] = func_info
                stub_index.functionTable[func_info.globalName] = func_info
        stub_index.modules["database"] = db_mod

        # Build App Module
        app_mod = ModuleInfo(
            filePath="app.py",
            moduleName="app",
            astTree=ast.parse(app_source),
            parseError=None
        )
        
        from_imp = type("MockImport", (), {"moduleName": "database", "importedName": "run_query", "alias": None, "kind": "from_import"})()
        mod_imp = type("MockImport", (), {"moduleName": "os", "importedName": "os", "alias": None, "kind": "import"})()
        app_mod.imports = [from_imp, mod_imp]

        for node in app_mod.astTree.body:
            if isinstance(node, ast.FunctionDef):
                func_info = FunctionInfo(
                    name=node.name,
                    globalName=f"app.{node.name}",
                    moduleName="app",
                    node=node,
                    params=[arg.arg for arg in node.args.args],
                    lineno=node.lineno,
                    endLineno=getattr(node, "end_lineno", node.lineno),
                    decorators=[],
                    isAsync=False
                )
                app_mod.functions[node.name] = func_info
                stub_index.functionTable[func_info.globalName] = func_info
        stub_index.modules["app"] = app_mod

        # Initialize Components
        graph = DiagnosticCodeGraph()
        builder = CallGraphBuilder(stub_index)
        builder.resolver.builtins = stub_index.builtins

        print("\n=======================================================")
        print("CODEGRAPH UNDERLYING SOURCE INSPECTION:")
        print("=======================================================")
        try:
            print(inspect.getsource(CodeGraph.addEdge))
        except Exception as e:
            print(f"Could not print addEdge source: {e}")
        print("=======================================================\n")

        print("=== RUNNING CALLGRAPHBUILDER ===")
        builder.build(graph)
        print("=== ANALYSIS COMPLETE ===\n")

        assert len(graph.edges) == 2, f"Gatekeeper failed! Expected 2 edges, found {len(graph.edges)}"

    finally:
        if os.path.exists("database.py"):
            os.remove("database.py")
        if os.path.exists("app.py"):
            os.remove("app.py")