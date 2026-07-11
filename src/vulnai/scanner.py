from dataclasses import dataclass, field
from collections import Counter
import traceback
import ast
from vulnai.analysis.intraprocedural.builder import Builder
from vulnai.analysis.intraprocedural.reachingdef import ReachingDefinitionAnalyzer
from vulnai.analysis.intraprocedural.usedef import UseDefAnalyzer
from vulnai.analysis.interprocedural.structured_storage.codebase_index_builder import CodebaseIndexBuilder
from vulnai.analysis.interprocedural.code_graph.graphbuilder import CodeGraphBuilder
from vulnai.analysis.interprocedural.code_graph.callgraphbuild import CallGraphBuilder
from vulnai.analysis.interprocedural.summary_and_graph.summary_builder import FunctionSummaryBuilder
from vulnai.analysis.interprocedural.summary_and_graph.summarystore import SummaryStore
from vulnai.analysis.interprocedural.summary_and_graph.taint_analyzer import InterproceduralTaintAnalyzer
from vulnai.analysis.vulnerabilities.rule_registry import RuleRegistry
from vulnai.analysis.vulnerabilities.rules import ALL_RULES


@dataclass
class ScanResult:
    target: str
    modules_indexed: int = 0
    functions_indexed: int = 0
    diagnostics_count: int = 0

    graph_nodes: int = 0
    graph_edges: int = 0
    edge_counts: dict[str, int] = field(default_factory=dict)

    summaries_built: int = 0
    summaries_failed: int = 0
    summary_errors: list[dict] = field(default_factory=list)

    vulnerabilities: list[dict] = field(default_factory=list)


class Scanner:
    def __init__(self):
        pass

    def load_rule_registry(self) -> RuleRegistry:
        return RuleRegistry(ALL_RULES)

    def build_function_maps(self, codebase_index):
        function_param_map = {}
        function_ast_map = {}

        for global_name, func_info in codebase_index.functionTable.items():
            function_param_map[global_name] = func_info.params
            function_ast_map[global_name] = func_info.node

        return function_param_map, function_ast_map

    # NOTE: NEW - Scans module/class scope for hardcoded secrets.
    # Function summaries intentionally skip code outside functions.
    def scan_module_level_patterns(self, codebase_index, registry: RuleRegistry) -> list[dict]:
        findings: list[dict] = []
        reported = set()
        secret_rules = [rule for rule in registry.patternRules if rule.cwe == "CWE-798"]

        if not secret_rules:
            return findings

        def matching_rules(name: str, literal: str):
            loweredName = name.lower()

            for rule in secret_rules:
                nameMatched = any(loweredName == sink.lower() for sink in rule.sinks)
                literalMatched = any(sink and sink in literal for sink in rule.sinks)

                if nameMatched or literalMatched:
                    yield rule

        def target_names(target: ast.AST) -> list[str]:
            if isinstance(target, ast.Name):
                return [target.id]

            if isinstance(target, ast.Attribute):
                return [target.attr]

            if isinstance(target, ast.Subscript):
                try:
                    return [ast.unparse(target.slice).strip().strip("'\"")]
                except Exception:
                    return []

            if isinstance(target, (ast.Tuple, ast.List)):
                names = []

                for elt in target.elts:
                    names.extend(target_names(elt))

                return names

            return []

        def add_finding(module_name: str, file_path: str, rule, matched_name: str, literal: str, node: ast.AST) -> None:
            sig = (module_name, rule.cwe, matched_name, getattr(node, "lineno", 0), literal)

            if sig in reported:
                return

            reported.add(sig)
            findings.append({
                "vulnerability": f"Static Pattern Match: {rule.name}",
                "cwe": rule.cwe,
                "caller": "N/A (Static Pattern)",
                "callee": module_name,
                "viaParameter": "None",
                "sinkReached": ast.unparse(node).strip(),
                "line": getattr(node, "lineno", "Unknown"),
                "contextId": "module_pattern_match",
                "file": file_path,
            })

        class ModulePatternVisitor(ast.NodeVisitor):
            # NOTE: NEW - Module/class pattern scan skips function bodies.
            # Function-level findings are already handled by FunctionSummaryBuilder.
            def __init__(self, module_name: str, file_path: str):
                self.module_name = module_name
                self.file_path = file_path

            def visit_FunctionDef(self, node):
                return

            def visit_AsyncFunctionDef(self, node):
                return

            def visit_Lambda(self, node):
                return

            def visit_Assign(self, node):
                self.check_assignment(node.targets, node.value, node)
                self.generic_visit(node.value)

            def visit_AnnAssign(self, node):
                self.check_assignment([node.target], node.value, node)
                if node.value:
                    self.generic_visit(node.value)

            def check_assignment(self, targets: list[ast.AST], value: ast.AST | None, node: ast.AST) -> None:
                if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value.strip():
                    for target in targets:
                        for name in target_names(target):
                            for rule in matching_rules(name, value.value):
                                add_finding(self.module_name, self.file_path, rule, name, value.value, node)

                if isinstance(value, ast.Dict):
                    for key_node, value_node in zip(value.keys, value.values):
                        if not (
                            isinstance(key_node, ast.Constant)
                            and isinstance(key_node.value, str)
                            and isinstance(value_node, ast.Constant)
                            and isinstance(value_node.value, str)
                            and value_node.value.strip()
                        ):
                            continue

                        for rule in matching_rules(key_node.value, value_node.value):
                            add_finding(self.module_name, self.file_path, rule, key_node.value, value_node.value, node)

        for module_name, module_info in codebase_index.modules.items():
            if not module_info.astTree:
                continue

            ModulePatternVisitor(module_name, module_info.filePath).visit(module_info.astTree)

        return findings

    def build_one_function_summary(self, func_info, registry, importAliasMap=None):
        """
        Runs the full intraprocedural pipeline for ONE function:

        AST function node
        -> CFG
        -> Reaching Definitions
        -> Use-Def
        -> FunctionSummary
        """

        func_node = func_info.node

        # 1. Build CFG
        cfg_builder = Builder()
        cfg_obj = cfg_builder.cfgBuild(func_node)

        # 2. Reaching Definition Analysis
        rda = ReachingDefinitionAnalyzer()

        # First collect all definitions globally for this function
        for block in cfg_obj.blocks:
            rda.defCollect(block)

        # Then compute GEN/KILL per block
        for block in cfg_obj.blocks:
            rda.defHandle(block)

        # Then compute IN/OUT fixed point
        rda.transferFunction(cfg_obj)

        # 3. Use-Def Analysis
        uda = UseDefAnalyzer()
        uda.analyze(cfg_obj, rda)

        # 4. Build Function Summary
        summary_builder = FunctionSummaryBuilder(uda, rda)
        summary = summary_builder.buildSummary(
            funcInfo=func_info,
            cfgObj=cfg_obj,
            registry=registry,
            importAliasMap=importAliasMap or {},
        )

        return summary

    def scan(self, target_path: str) -> ScanResult:
        result = ScanResult(target=target_path)

        print(f"[*] Starting vulnAI scan on: {target_path}")

        # ------------------------------------------------------------
        # Phase 1: Build Codebase Index
        # ------------------------------------------------------------
        print("[-] Building CodebaseIndex...")

        index_builder = CodebaseIndexBuilder()
        codebase_index = index_builder.build(target_path)

        result.modules_indexed = len(codebase_index.modules)
        result.functions_indexed = len(codebase_index.functionTable)
        result.diagnostics_count = len(codebase_index.diagnostics)

        print(f"    Modules indexed: {result.modules_indexed}")
        print(f"    Functions indexed: {result.functions_indexed}")
        print(f"    Diagnostics: {result.diagnostics_count}")

        # ------------------------------------------------------------
        # Phase 2: Build Base CodeGraph
        # ------------------------------------------------------------
        print("[-] Building base CodeGraph...")

        graph_builder = CodeGraphBuilder()
        graph = graph_builder.build(codebase_index)

        # ------------------------------------------------------------
        # Phase 3: Add CALLS edges
        # ------------------------------------------------------------
        print("[-] Building CallGraph edges...")

        call_graph_builder = CallGraphBuilder(codebase_index)
        call_graph_builder.build(graph)

        result.graph_nodes = len(graph.nodes)
        result.graph_edges = len(graph.edges)
        result.edge_counts = dict(Counter(edge.edgeType for edge in graph.edges))

        print(f"    Graph nodes: {result.graph_nodes}")
        print(f"    Graph edges: {result.graph_edges}")
        print(f"    Edge counts: {result.edge_counts}")

        # ------------------------------------------------------------
        # Phase 4: Load vulnerability rules
        # ------------------------------------------------------------
        print("[-] Loading vulnerability rules...")

        registry = self.load_rule_registry()

        print(f"    Taint rules: {len(registry.taintRules)}")
        print(f"    Pattern rules: {len(registry.patternRules)}")

        # ------------------------------------------------------------
        # Phase 5: Build Function Summaries
        # ------------------------------------------------------------
        print("[-] Building function summaries...")

        summary_store = SummaryStore()

        for global_name, func_info in codebase_index.functionTable.items():
            try:
                module_info = codebase_index.modules.get(func_info.moduleName)
                importAliasMap = getattr(module_info, "importAliasMap", {}) if module_info else {}

                summary = self.build_one_function_summary(
                    func_info=func_info,
                    registry=registry,
                    importAliasMap=importAliasMap,
                )

                summary_store.addSummary(summary)
                result.summaries_built += 1

            except Exception as exc:
                result.summaries_failed += 1
                result.summary_errors.append({
                    "function": global_name,
                    "error": str(exc),
                    "traceback": traceback.format_exc(),
                })

                print(f"    [!] Failed summary for {global_name}: {exc}")

        print(f"    Summaries built: {result.summaries_built}")
        print(f"    Summaries failed: {result.summaries_failed}")

        # ------------------------------------------------------------
        # Phase 6: Build maps for interprocedural analyzer
        # ------------------------------------------------------------
        print("[-] Building function maps...")

        function_param_map, function_ast_map = self.build_function_maps(codebase_index)

        # ------------------------------------------------------------
        # Phase 7: Run Interprocedural Taint Analysis
        # ------------------------------------------------------------
        print("[-] Running interprocedural taint analysis...")

        taint_analyzer = InterproceduralTaintAnalyzer(
            store=summary_store,
            functionParamMap=function_param_map,
            functionAstMap=function_ast_map,
            registry=registry,
        )

        vulnerabilities = taint_analyzer.analyze(graph)
        # NOTE: NEW - Add non-function pattern findings after taint analysis.
        # These findings do not participate in propagation; they are direct facts.
        vulnerabilities.extend(self.scan_module_level_patterns(codebase_index, registry))
        result.vulnerabilities = vulnerabilities

        print("[+] Scan complete.")
        print(f"    Vulnerabilities found: {len(result.vulnerabilities)}")

        return result


def print_scan_result(result: ScanResult):
    print("\n==============================")
    print(" vulnAI Scan Result")
    print("==============================")

    print(f"Target: {result.target}")
    print(f"Modules indexed: {result.modules_indexed}")
    print(f"Functions indexed: {result.functions_indexed}")
    print(f"Diagnostics: {result.diagnostics_count}")

    print(f"\nGraph nodes: {result.graph_nodes}")
    print(f"Graph edges: {result.graph_edges}")
    print(f"Edge counts: {result.edge_counts}")

    print(f"\nSummaries built: {result.summaries_built}")
    print(f"Summaries failed: {result.summaries_failed}")

    if result.summary_errors:
        print("\nSummary Errors:")
        for err in result.summary_errors[:10]:
            print(f"- {err['function']}: {err['error']}")

        if len(result.summary_errors) > 10:
            print(f"... and {len(result.summary_errors) - 10} more")

    print(f"\nVulnerabilities found: {len(result.vulnerabilities)}")

    if not result.vulnerabilities:
        print("\nNo vulnerabilities reported.")
        return

    print("\nFindings:")
    for i, vuln in enumerate(result.vulnerabilities, start=1):
        print(f"\n[{i}] {vuln.get('vulnerability', 'Unknown Vulnerability')}")
        print(f"    CWE: {vuln.get('cwe')}")
        print(f"    Caller: {vuln.get('caller')}")
        print(f"    Callee: {vuln.get('callee')}")
        print(f"    Via Parameter: {vuln.get('viaParameter')}")
        print(f"    Sink Reached: {vuln.get('sinkReached')}")
        print(f"    Line: {vuln.get('line')}")
        print(f"    Context: {vuln.get('contextId')}")
