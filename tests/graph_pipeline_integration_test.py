
from pathlib import Path

# Core Data Structures
from vulnai.analysis.interprocedural.structured_storage.codebase_index import CodebaseIndex
from vulnai.analysis.interprocedural.code_graph.graph import CodeGraph

# Pipeline Builders
from vulnai.analysis.interprocedural.structured_storage.codebase_index_builder import CodebaseIndexBuilder
from vulnai.analysis.interprocedural.code_graph.graphbuilder import CodeGraphBuilder
from vulnai.analysis.interprocedural.code_graph.callgraphbuild import CallGraphBuilder


def test_end_to_end_call_graph_resolution(tmp_path: Path):
    """
    REAL INTEGRATION TEST:
    Validates the entire pipeline from physical files to interprocedural call extraction,
    ensuring structural edges (CONTAINS, IMPORTS) do not pollute behavioral edge (CALLS) assertions.
    """
    
    # ==========================================
    # 1. SETUP: Write a real mini-codebase to disk
    # ==========================================
    
    db_file = tmp_path / "db.py"
    db_file.write_text("def execute_query(query_string):\n    pass\n")

    auth_file = tmp_path / "auth.py"
    auth_file.write_text("def verify_token(token):\n    return True\n")

    app_file = tmp_path / "app.py"
    app_file.write_text(
        "from auth import verify_token\n"
        "import db\n\n"
        "def process_request(req_data):\n"
        "    if verify_token('secret'):\n"
        "        db.execute_query('SELECT *')\n"
        "    print('Done')\n"
    )

    # ==========================================
    # 2. EXECUTE: Run the real processing pipeline
    # ==========================================
    
   
    # 1. Build the index (Returns populated index)
    # 1. Build the index
    index_builder = CodebaseIndexBuilder()
    index = index_builder.build(str(tmp_path))
    
    # 2. Build the structural skeleton
    graph_builder = CodeGraphBuilder()
    graph = graph_builder.build(index)
    
    # 3. Resolve the call edges
    call_builder = CallGraphBuilder(index)
    call_builder.build(graph)

    # ==========================================
    # 3. VERIFY: Assert Pipeline Correctness
    # ==========================================
    
    # --- A. Node and Index Verification ---
    assert "app.process_request" in index.functionTable
    assert "function:app.process_request" in graph.nodes
    assert "function:db.execute_query" in graph.nodes
    assert "function:auth.verify_token" in graph.nodes

    # --- B. Edge Filtering Helpers ---
    # Fixed: Explicitly targets the 'edgeType' attribute of the GraphEdge class
    def is_call_edge(edge):
        return getattr(edge, "edgeType", "") in ("CALL", "CALLS")
    
    call_edges = [e for e in graph.edges if is_call_edge(e)]
    
    # --- C. Global Edge Assertions ---
    assert len(call_edges) == 2, f"Expected exactly 2 CALL edges, found {len(call_edges)}"

    def call_edge_exists(source: str, target: str) -> bool:
        return any(e.source == source and e.target == target for e in call_edges)

    assert call_edge_exists("function:app.process_request", "function:auth.verify_token"), \
        "Failed to resolve `from_import` integration across files."
        
    assert call_edge_exists("function:app.process_request", "function:db.execute_query"), \
        "Failed to resolve `import module` attribute integration across files."

    # --- D. Adjacency Map Assertions ---
    # Filter adjacency lists to separate structural 'CONTAINS' from behavioral 'CALLS'
    process_request_outgoing_calls = [e for e in graph.outgoing.get("function:app.process_request", []) if is_call_edge(e)]
    db_execute_incoming_calls = [e for e in graph.incoming.get("function:db.execute_query", []) if is_call_edge(e)]
    auth_verify_incoming_calls = [e for e in graph.incoming.get("function:auth.verify_token", []) if is_call_edge(e)]

    assert len(process_request_outgoing_calls) == 2, "Outgoing calls map is missing edges."
    assert len(db_execute_incoming_calls) == 1, "Incoming calls map for db.execute_query is incorrect."
    assert len(auth_verify_incoming_calls) == 1, "Incoming calls map for auth.verify_token is incorrect."

    # Optional sanity check: ensure the structural edges DO exist (proving we aren't just empty)
    db_execute_incoming_all = graph.incoming.get("function:db.execute_query", [])
    assert len(db_execute_incoming_all) > 1, "Expected structural edges (CONTAINS) plus CALL edges, but got <= 1."