import ast
from collections import defaultdict
from typing import List, Dict, Set, Optional, Tuple
from vulnai.analysis.interprocedural.code_graph.graph import CodeGraph
from vulnai.analysis.interprocedural.summary_and_graph.summarystore import SummaryStore


#Walks the call graph edges, checks the summaries, and traces cross-file vulnerabilities
class InterproceduralTaintAnalyzer:

    #functionParamMap: func names -> an ordered list of their params
    #functionAstMap is tracking raw AST node bodies of functions so it can run localized scans when needed
    def __init__(self, store: SummaryStore, functionParamMap: Dict[str, List[str]], functionAstMap: Dict[str, ast.FunctionDef]):
        self.store = store
        self.functionParamMap = functionParamMap
        self.functionAstMap = functionAstMap
        
        #Maps: (function name, context id) -> set of local tainted var/param names
        self.localTaintScopes: Dict[Tuple[str, int], Set[str]] = defaultdict(set)
        
        #function names -> a set of their currently active context IDs
        self.activeContexts: Dict[str, Set[int]] = defaultdict(set)
        self._bootstrap_contexts()


    #Inits all known functions with a base root context id (which is 0)
    def _bootstrap_contexts(self) -> None:
        for funcName in self.functionParamMap.keys():
            self.activeContexts[funcName].add(0)


    #Scans a caller func's AST to see exactly which local var captured a function call's return value
    def _get_assignedVariable(self, callNode: ast.Call, callerfuncName: str) -> Optional[str]:
        callerAst = self.functionAstMap.get(callerfuncName)
        if not callerAst:
            return None
            
        targetRaw = ast.unparse(callNode).strip()

        for node in ast.walk(callerAst):

            if isinstance(node, ast.Assign):
                
                #Goes into the rhs of the assignment (node.value). 
                #If it finds a function call that matches the targetRaw string signature, 
                #it proves this line is where the call happened
                for sub in ast.walk(node.value):

                    if isinstance(sub, ast.Call) and ast.unparse(sub).strip() == targetRaw:
                        
                        #Filter out things like tuples
                        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                            return node.targets[0].id
        return None



    def analyze(self, graph: CodeGraph) -> List[dict]:
        vulnerabilities = []
        reported = set() #aka bugs
        
        changed = True
        while changed:
            changed = False
            
            for edge in graph.edges:
                if edge.edgeType != "CALLS":
                    continue
                
                callSite = edge.metadata.get("callSite") #tries to check if the metadeta tells us where this func call takes place
                if not callSite:
                    continue
                
                caller = callSite.callerFunc  
                callee = callSite.calleeFunc  
                callNode = callSite.node   
                lineno = callSite.lineno     
                
                summary = self.store.getSummary(callee)
                if not summary:
                    continue

                #Isolate the callee's execution context specifically to this line call
                calleeCtxID = lineno
                
                #Iterate through all live contexts currently driving the caller function
                for callerCtxID in list(self.activeContexts[caller]):
                    
                    #PASS 1: Shifting taint from caller args to callee params
                    calleeParamNames = self.functionParamMap.get(callee, [])

                    for argPos, argNode in enumerate(callNode.args):
                        if argPos < len(calleeParamNames):
                            paramName = calleeParamNames[argPos]
                            
                            #Check taint status inside the caller's specific execution context
                            if isinstance(argNode, ast.Name) and argNode.id in self.localTaintScopes[(caller, callerCtxID)]:

                                if paramName not in self.localTaintScopes[(callee, calleeCtxID)]:
                                    self.localTaintScopes[(callee, calleeCtxID)].add(paramName)
                                    self.activeContexts[callee].add(calleeCtxID)
                                    changed = True

                    #PASS 2: Pulling Return Taint from Callee Back to Caller Variable
                    returnsTaint = summary.returnsTainted


                    #If the function wasn't unconditionally toxic, it looks at its parameter dependency mapping. 
                    #It checks: "Did an active parameter that is currently toxic inside this line's context flow into the return value?"
                    if not returnsTaint:
                        
                        for p in summary.taintedReturnParams:
                            if p in self.localTaintScopes[(callee, calleeCtxID)]:
                                returnsTaint = True
                                break
                                
                    if returnsTaint:
                        assignedVar = self._get_assignedVariable(callNode, caller)
                        if assignedVar and assignedVar not in self.localTaintScopes[(caller, callerCtxID)]:
                            self.localTaintScopes[(caller, callerCtxID)].add(assignedVar)
                            changed = True

                    #PASS 3: Verify Sinks Against the Isolated Callee Context State
                    for activeParam in self.localTaintScopes[(callee, calleeCtxID)]:
                        if activeParam in summary.paramsToSinks:
                            sinks_hit = summary.paramsToSinks[activeParam]
                            
                            sig = (caller, callerCtxID, callee, calleeCtxID, activeParam, lineno)
                            if sig not in reported:
                                reported.add(sig)
                                vulnerabilities.append({
                                    "vulnerability": "Cross-File Taint Flow Detected",
                                    "caller": caller,
                                    "callee": callee,
                                    "via_parameter": activeParam,
                                    "internal_sinks_reached": sinks_hit,
                                    "line": lineno,
                                    "context_id": f"callsite_line_{calleeCtxID}"
                                })
                            
        return vulnerabilities #for generating dev reports. The final list of all the vulnerabilities analyzer shows to the developer