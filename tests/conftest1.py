import os
import ast
import pytest
from vulnai.analysis.interprocedural.structured_storage.codebase_index import CodebaseIndex, ModuleInfo, FunctionInfo

@pytest.fixture
def mock_project_index():
    """Builds a thoroughly populated CodebaseIndex explicitly isolated by modules."""
    index = CodebaseIndex(".")
    
    # Define the raw source strings as independent mock units to avoid shared-file parsing side effects
    db_source = """
def run_query(sql_string):
    pass
"""

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

    # --- 1. Populate Database Module ---
    db_mod = ModuleInfo(
        filePath="database.py",
        moduleName="database",
        astTree=ast.parse(db_source),
        parseError=None
    )
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
            index.functionTable[func_info.globalName] = func_info
            
    index.modules["database"] = db_mod

    # --- 2. Populate App Module ---
    app_mod = ModuleInfo(
        filePath="app.py",
        moduleName="app",
        astTree=ast.parse(app_source),
        parseError=None
    )
    
    # Mock precise imports expected by SymbolResolver
    from_imp = type("MockImport", (), {
        "moduleName": "database", "importedName": "run_query", "alias": None, "kind": "from_import"
    })()
    mod_imp = type("MockImport", (), {
        "moduleName": "os", "importedName": "os", "alias": None, "kind": "import"
    })()
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
            index.functionTable[func_info.globalName] = func_info
            
    index.modules["app"] = app_mod
    
    # Inject builtins to safeguard resolver plain-name checks
    index.builtins = {"print", "len"}
    
    return index