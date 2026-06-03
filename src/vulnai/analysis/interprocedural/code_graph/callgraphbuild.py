import ast
from vulnai.analysis.interprocedural.structured_storage.codebase_index import CodebaseIndex
from vulnai.analysis.interprocedural.code_graph.edges import GraphEdge
from vulnai.analysis.interprocedural.code_graph.symbol_resolver import SymbolResolver
from vulnai.analysis.interprocedural.code_graph.resolver import ResolutionKind, CallSiteInfo
from vulnai.analysis.interprocedural.code_graph.graph import CodeGraph

#Which function calls which function?
class CallGraphBuilder:
    def __init__(self, index: CodebaseIndex):
        self.index = index
        self.resolver = SymbolResolver(index)
        self.typeCalls = "CALLS"

    def build(self, graph: CodeGraph) -> None:
        for moduleName, modInfo in self.index.modules.items():
            for funcName, funcData in modInfo.functions.items():
                sourceFuncId = f"function:{funcData.globalName}"

                for node in ast.walk(funcData.node):
                    if isinstance(node, ast.Call):
                        
                        #Passes full execution context (Module + Current Function Container)
                        resolved = self.resolver.resolveCall(node, moduleName, funcName)
                        
                        #Checks if the function is a local fucntion from anywhere in the codebase / an import / it is a module attribute / a Built-In (for builtin, the globalName returns None, so the condition fails). 
                        #If not, totally ignore it,
                        #because the codebase indexer only scanned the project folder (and didn't scan Python's internal standard library files)
                    
                        #If we dont ignore, the builder crashes, bcz the target node was never created, because it was never scanned

                        if resolved.globalName and resolved.kind in {ResolutionKind.localFunction, ResolutionKind.fromImport, ResolutionKind.moduleAttribute}:

                            targetFuncId = f"function:{resolved.globalName}"
                            
                            callSite = CallSiteInfo(
                                lineno=node.lineno,
                                callerFunc=funcData.globalName,
                                calleeFunc=resolved.globalName,
                                resolutionKind=resolved.kind,
                                confidence=resolved.confidence,
                                node=node
                            )
                            
                            callsEdge = GraphEdge(
                                source=sourceFuncId, 
                                target=targetFuncId, 
                                edgeType=self.typeCalls,
                                metadata={"callSite": callSite}
                            )
                            
                            graph.addEdge(callsEdge)