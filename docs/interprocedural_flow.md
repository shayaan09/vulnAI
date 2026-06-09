# Interprocedural Analysis Architecture Notes

This interprocedural design was extremely complex for me to keep track of, and I got lost multiple times because I either:

1. Forgot the chronological flow and general connections between data
2. Confused when two classes were built on top of each other, meaning, when the other class was a layer above the other one (like call graph being ontop of codegraph). It was incredibly difficult to keep track of what variable in layer 2 connected to which structure in layer 1

There are multiple components, class info, data structures and passes you need to keep track of at once and I was in a constant state of working memory overload.

This file is crucial to follow and honestly I should have made this during the building of this and not after haha, but this is for future reference.

---

## Class Information

### 1. Structured Storage (The Data Harvester)

- **CodebaseIndex:** The master database of raw code facts. It indexes the entire project folder.
- **ModuleInfo:** A storage record holding details about an individual python file (its path, name, imports, etc).
- **FunctionInfo:** A storage record for a single function declaration, holding its parameters, string name, and a pointer to its raw ast FunctionDef node tree.
- **ImportInfo:** A record tracking what a file imports (e.g., from os import path).
- **DiagnosticInfo:** A monitoring log capturing parsing telemetry, errors, and indexing stats.

### 2. Code Graph & Symbol Resolution (The Paving Crew)

- **CodeGraph:** The container class holding arrays and adjacency maps (incoming/outgoing). It represents the relationships between the items inside CodebaseIndex.
- **GraphNode:** A lightweight, immutable "dumb record" representing a specific entity (like a Function) in the network.
- **GraphEdge:** A structural vector tracking a relationship link connecting two node IDs together.
- **CallSiteInfo:** A metadata payload attached to a GraphEdge documenting the exact context of a function call (line number, raw ast.Call node, argument names).
- **ResolvedSymbol:** A temporary data envelope created during lookups to hold what a function call points to.
- **ResolutionKind:** A string constant enum used by the resolver to classify call types (e.g BUILTIN).
- **Call Graph:** The execution highway formed inside the CodeGraph container strictly out of CALLS edges. Answers: Which function calls which function?

### 3. Summary & Taint (The Security Brain)

- **FunctionSummary:** A passport blueprint mapping a function's behavior (which parameters trigger sinks, what returns are tainted).
- **SummaryStore:** A global dictionary database housing all the pre-computed FunctionSummary passports.
- **InterproceduralTaintAnalyzer:** The master judge. It walks the call graph edges, checks the summaries, and traces cross-file vulnerabilities.

---

## Chronological Flow: TLDR

Files → CodebaseIndexBuilder → CodebaseIndex → CodeGraphBuilder → CodeGraph → CallGraphBuilder → FunctionSummaryBuilder → SummaryStore → InterproceduralTaintAnalyzer


---

## Chronological Flow: Detailed

### Phase 1: Localized Harvesting & Blueprint Drafting

This phase works strictly line-by-line within single functions, completely blind to other files.

1. **Code Discovery:** The engine initializes CodebaseIndex and scans the project folder. For every Python file found, it creates a ModuleInfo record, registers its ImportInfo, and extracts every function as a FunctionInfo record (storing its parameters and raw AST). Any syntax hiccups are logged in DiagnosticInfo.

2. **Intraprocedural Fixed-Point Loop:** The engine loops through each FunctionInfo's AST using the FunctionSummaryBuilder. It spins an isolated `while changed:` loop to map how local variables contaminate each other inside that individual function.

3. **Passport Generation:** Once local dataflow stabilizes, a final pass runs. If a function hits an internal sink, or directly returns user input, that behavior is permanently recorded inside a FunctionSummary dataclass instance.

4. **Database Storage:** The newly minted passport is saved into the global SummaryStore. The engine then drops the heavy AST structures for that function out of memory, keeping only its lightweight behavioral contract. Once Phase 1 (the FunctionSummaryBuilder) finishes walking that tree, we don't care how the function did its job locally anymore. We just care about the security verdict (what is recieved tainted, what is returned tainted, etc)

### Phase 2: Structural Road Mapping & Control-Flow

This phase links the independent functions together by establishing structural execution routes.

1. **Infrastructure Initialization:** An empty CodeGraph object is instantiated to act as a shared graph storage vault. The system creates a lightweight GraphNode for every function registered in our codebase index and adds it to the graph.

2. **Call Site Detection:** The CallGraphBuilder is built. It loops through all the saved functions inside the CodebaseIndex and walks their AST blocks, searching exclusively for ast.Call expressions.

3. **Symbol Resolution:** When the builder encounters a function call (like `db.run_query(payload)`), it hands the node over to the SymbolResolver. The resolver analyzes scope, maps imports, and returns a ResolvedSymbol stamped with a ResolutionKind (e.g proving it points to a local project function).

4. **Edge Manufacturing:** If the call targets an internal function, the builder constructs a CallSiteInfo payload capturing the exact line number (lineno), caller name, callee name, and the raw ast.Call node object.

5. **Graph Locking:** The builder wraps that CallSiteInfo into a GraphEdge stamped with `edgeType="CALLS"`. It executes `graph.addEdge(callsEdge)`. The graph updates its internal outgoing and incoming lookups, anchoring the edge in place. The conceptual Call Graph view is now fully paved.

### Phase 3: Global Taint Routing & Vulnerability

The infrastructure is complete; the final phase traces dynamic data flows globally across files.

1. **Analyzer Startup:** The InterproceduralTaintAnalyzer initializes. It boots up its `self.activeContexts` registry, seeding every function in the codebase with a baseline, context-sensitive root identifier of Context 0 via its internal bootstrapping loop.

2. **The Interprocedural Loop:** The analyzer enters its global `while changed:` fixed point execution pass. It streams through the CodeGraph's flat list of edges, checking if `edge.edgeType == "CALLS"`.

3. **Context Isolation:** The moment it processes a valid call edge, it extracts the embedded CallSiteInfo dataclass out of the edge metadata. It establishes an isolated context ID for the callee function based on the exact calling line number (`calleeCtxID = lineno`).

4. **The Argument Bridge (Pass 1):** The analyzer checks the caller's active taint context scope. If the variable passed as an argument is flagged as toxic, it reaches across the file boundary, flags the corresponding parameter variable name as toxic inside the callee's isolated context scope, and flags `changed = True`.

5. **The Blueprint Consultation (Pass 2 & 3):** Instead of diving deep into the callee's code, the analyzer queries the SummaryStore:

   1. **Sink Verification:** It cross-references the callee's newly poisoned parameter against the pre-calculated `summary.paramsToSinks` blueprint checklist. If that parameter maps to a registered sink, it raises a flag, compiles the security trace, and pushes a dict into the vulnerabilities array.

   2. **Return Propagation:** It checks `summary.taintedReturnParams`. If a toxic parameter is known to flow into the function's return expression, the analyzer flips its internal `returnsTaint` flag to True.

6. **The Capturing Pass:** If `returnsTaint` is proven true, the analyzer runs its helper method to find the local variable capturing the data on the left-hand side of the call node inside the caller function's AST. It poisons that local variable inside the caller's active context scope and sets `changed = True`.

7. **Convergence:** The analyzer repeats this global edge traversal loop continuously. Once taint facts stop expanding across the network, the loop stabilizes, drops out, and returns the compiled, validated inventory of architectural vulnerabilities.

---

## Original Handwritten Flow Diagram

This document is based on the original handwritten flow map I used while designing and debugging VulnAI’s intraprocedural and interprocedural taint analysis pipeline.

[View the original handwritten flow diagram](./interprocedural-flow.pdf)