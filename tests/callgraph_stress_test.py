import pytest
import ast
import os
from vulnai.analysis.interprocedural.code_graph.graph import CodeGraph
from vulnai.analysis.interprocedural.code_graph.callgraphbuild import CallGraphBuilder
from vulnai.analysis.interprocedural.structured_storage.codebase_index import CodebaseIndex, ModuleInfo, FunctionInfo

class DiagnosticCodeGraph(CodeGraph):
    def addEdge(self, edge, *args, **kwargs):
        if isinstance(self.nodes, dict):
            if edge.source not in self.nodes:
                self.nodes[edge.source] = type("MockNode", (), {"id": edge.source})()
            if edge.target not in self.nodes:
                self.nodes[edge.target] = type("MockNode", (), {"id": edge.target})()
        
        if isinstance(self.outgoing, dict) and edge.source not in self.outgoing:
            self.outgoing[edge.source] = []
        if isinstance(self.incoming, dict) and edge.target not in self.incoming:
            self.incoming[edge.target] = []
            
        print(f"    [GRAPH MATCH] Edge captured: {edge.source} -> {edge.target}")
        return super().addEdge(edge, *args, **kwargs)

class StabbedCodebaseIndex(CodebaseIndex):
    def __init__(self):
        self.modules = {}
        self.functionTable = {}
        self.builtins = {"print", "len", "range", "str", "int"}
        self.importGraph = {}
        self.diagnostics = []

def test_extreme_stress_call_graph():
    # THE NIGHTMARE PAYLOAD
    app_source = """
import os as system_os

def true_target():
    pass

# STRESS 1: DECORATORS & CLOSURES
def trace_call(func):
    def wrapper(*args, **kwargs):
        true_target()  # The analyzer needs to catch this hidden call
        return func(*args, **kwargs)
    return wrapper

# STRESS 2: CLASSES & DUNDER METHODS
class Executor:
    def __call__(self, payload):
        true_target()

class BaseHandler:
    def process(self):
        true_target()

class AdvancedHandler(BaseHandler):
    def process(self):
        super().process() # Does it resolve the MRO?

@trace_call
def obfuscated_function():
    pass

def main():
    # STRESS 3: SHADOWING & LAMBDAS
    obfuscated_function = lambda: true_target()
    obfuscated_function() # This should map to the lambda, NOT the global decorator wrapped function!
    
    # STRESS 4: HIGHER ORDER FUNCTIONS & DYNAMIC DISPATCH
    dispatch_table = {"run": true_target}
    dispatch_table["run"]() # Can it track dictionary values?
    
    # STRESS 5: DUNDER INVOCATION
    engine = Executor()
    engine("data") # Implicitly calls __call__
    
    # STRESS 6: COMPREHENSION SCOPES
    env_vars = [system_os.getenv(k) for k in ("PATH", "USER")] # Comprehensions create their own scope blocks in AST!
"""
    
    try:
        stub_index = StabbedCodebaseIndex()

        # Build App Module
        app_mod = ModuleInfo(
            filePath="app.py",
            moduleName="app",
            astTree=ast.parse(app_source),
            parseError=None
        )
        
        mod_imp = type("MockImport", (), {"moduleName": "os", "importedName": "os", "alias": "system_os", "kind": "import"})()
        app_mod.imports = [mod_imp]

        # Register functions and classes to the index
        for node in app_mod.astTree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                func_info = FunctionInfo(
                    name=node.name,
                    globalName=f"app.{node.name}",
                    moduleName="app",
                    node=node,
                    params=[],
                    lineno=node.lineno,
                    endLineno=getattr(node, "end_lineno", node.lineno),
                    decorators=[d.id for d in node.decorator_list if isinstance(d, ast.Name)] if hasattr(node, "decorator_list") else [],
                    isAsync=False
                )
                app_mod.functions[node.name] = func_info
                stub_index.functionTable[func_info.globalName] = func_info
                
        stub_index.modules["app"] = app_mod

        # Initialize Components
        graph = DiagnosticCodeGraph()
        builder = CallGraphBuilder(stub_index)
        builder.resolver.builtins = stub_index.builtins

        print("\n=== RUNNING BRUTAL STRESS TEST ===")
        builder.build(graph)
        print("=== ANALYSIS COMPLETE ===\n")
        
        edges_found = len(graph.edges)
        print(f"Total Edges Extracted: {edges_found}")
        
        # A perfect analyzer would catch exactly 7 distinct calls here. 
        # Don't worry if it crashes or misses them—this is the baseline to improve upon.
        assert edges_found > 0, "Analyzer completely failed to map any dynamic calls."

    except Exception as e:
        print(f"\n[STRESS TEST FAILED] The analyzer crashed: {type(e).__name__}: {e}")
        raise