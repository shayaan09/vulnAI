import ast
from collections import defaultdict
from vulnai.analysis.interprocedural.code_graph.graph import CodeGraph
from vulnai.analysis.interprocedural.summary_and_graph.summarystore import SummaryStore


#Walks the call graph edges, checks the summaries, and traces cross-file vulnerabilities
#Argument: What the caller function CALLS. execute(user), use is the argument
#Parameter: what the callee has DEFINED for the placeholder name

#How it works:
#1- Context Isolation (Setting up the Stage)
#Every time a function call is crossed, the analyzer sets up a new execution bucket for the function being called, tagged with its literal calling line number (calleeCtxId = lineno). This stops data flows from different lines of code from corrupting each other.

#2- The Argument Check (Pass 1)
#What it does: Pours threat labels into the called function.
#The Rule: If a variable passed as an argument is carrying any active threat labels inside the caller's bucket, Pass 1 copies those exact threat labels straight onto the matching input parameter inside the callee's fresh bucket.

#3- The Return Check (Pass 2)
#What it does: Pulls surviving threats out of the called function. basically asks: Does the specific parameter we just marked tainted in Pass 1 travel down a code path and crash directly into a dangerous sink like os.system inside this function?
#The Rule: It checks the blueprint's summary.taintedReturnParams map. If any parameter currently marked as tainted is known to escape out through the function, the analyzer raises a flag.

#4- The Sink Check (Pass 3)
#What it does: Catches cross-file bugs by looking inside the called function's summary.
#The Rule: It takes the newly tainted parameter from Pass 1 and checks it against the pre-calculated summary.paramsToSinks checklist. If that parameter maps directly to a dangerous operation inside, it logs a definitive Cross-File Vulnerability right there.

#5- The Capture Pass (Finalizing the Spill)
#What it does: Spills the returned threat back into the original function.
#The Rule: If the return leak flag was raised, the engine looks at the left-hand side of the calling line to see who received the payload (e.g x = call()). It adds those escaping threat labels onto variable x back inside the caller's bucket.

#6. Fixed-Point Convergence (The Rinse and Repeat, was a PAIN to build. emphasis on PAIN)
#The analyzer loops over every execution path in the code graph again and again. If a pass completes and no new variable captures a new label, the data flows have stabilized. The engine stops and drops out the final security report.
class InterproceduralTaintAnalyzer:

    #functionParamMap: func names -> a list of their params
    #functionAstMap is tracking raw AST node bodies of functions so it can run localized scans when needed
    def __init__(self, store: SummaryStore, functionParamMap: dict[str, list[str]], functionAstMap: dict[str, ast.FunctionDef]):
        self.store = store
        self.functionParamMap = functionParamMap
        self.functionAstMap = functionAstMap
        
        #(function name, context id) -> varName -> set of active CWE ids
        self.localTaintScopes: dict[tuple[str, int], dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
        
        #function names -> a set of their currently active context IDs
        self.activeContexts: dict[str, set[int]] = defaultdict(set)
        self.contextInit()


    #Inits all known functions with a base root context id (which is 0)
    def contextInit(self) -> None:
        for funcName in self.functionParamMap.keys():
            self.activeContexts[funcName].add(0)


    #Scans a caller func's AST to see exactly which local var got assigned a funct call's return value
    def getAssignedVar(self, callNode: ast.Call, callerfuncName: str) -> str | None:
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


    def extractAssignedNames(self, target: ast.AST) -> set[str]:
        assignedNames = set()

        if isinstance(target, ast.Name):
            assignedNames.add(target.id)

        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                assignedNames.update(self.extractAssignedNames(elt))

        return assignedNames


    def getAssignedVarsFromParentStmt(self, callNode: ast.Call, parentStmt: ast.stmt | None) -> set[str]:
        if not parentStmt:
            return set()

        #like x = call()
        if isinstance(parentStmt, ast.Assign):
            if parentStmt.value is callNode:
                assignedVars = set()

                for target in parentStmt.targets:
                    assignedVars.update(self.extractAssignedNames(target))

                return assignedVars

            return set()

        #like x: str = call()
        if isinstance(parentStmt, ast.AnnAssign):
            if parentStmt.value is callNode:
                return self.extractAssignedNames(parentStmt.target)

            return set()

        #like x += call()
        if isinstance(parentStmt, ast.AugAssign):
            if parentStmt.value is callNode:
                return self.extractAssignedNames(parentStmt.target)

            return set()

        #like x := call()
        #Usually parentStmt is something like: if (x := call()):
        #or an expr stmt containing the walrus expr
        for node in ast.walk(parentStmt):
            if isinstance(node, ast.NamedExpr):
                if node.value is callNode:
                    return self.extractAssignedNames(node.target)

        return set()

    def analyze(self, graph: CodeGraph) -> list[dict]:
        vulnerabilities = [] #stores final report
        reported = set() #stores bugs, tuple: (caller, callerCtx, callee, calleeCtx, param, cwe, sink, line)
        
        changed = True
        while changed:
            changed = False
            
            for edge in graph.edges:
                if edge.edgeType != "CALLS":
                    continue
                
                callSiteInfo = edge.metadata.get("callSite") #tries to check if the metadeta tells us where this func call takes place
                if not callSiteInfo:
                    continue
                
                lineno = callSiteInfo.lineno
                callerFunc = callSiteInfo.callerFunc  
                calleeFunc = callSiteInfo.calleeFunc  
                callNode = callSiteInfo.node   
                     
                
                summary = self.store.getSummary(calleeFunc)
                if not summary:
                    continue

                #Isolate the callee's execution context specifically to this line call
                calleeCtxID = lineno #gets us call site context, if a func calls a tainted param on line 14, but a safe one on like 800, line 800 should not be treated as tainted
                calleeParamNames = self.functionParamMap.get(calleeFunc, [])
                

                #Iterate through all live contexts currently driving the caller function
                for callerCtxID in list(self.activeContexts[callerFunc]):
                    currentCallerScope = self.localTaintScopes[(callerFunc, callerCtxID)] #extrcat the state of every var at this specific context of caller

                    #PASS 1: Shifting taint from caller args to callee params
                    #This pass handles ENTERING a function. It checks the variables passing INTO a val
                    for argPos, argNode in enumerate(callNode.args):

                        #Verifies that the caller isn't passing more positional args than the func's definition supports
                        #If it matches a valid index, it maps that index straight to the param string name (paramName)
                        if argPos < len(calleeParamNames):
                            paramName = calleeParamNames[argPos]
                            
                            #Check taint status inside the caller's execution context
                            if isinstance(argNode, ast.Name) and argNode.id in currentCallerScope:
                                activeArgumentCwes = currentCallerScope[argNode.id]
                                
                                if activeArgumentCwes:
                                    currentCalleeScope = self.localTaintScopes[(calleeFunc, calleeCtxID)]
                                    oldLen = len(currentCalleeScope[paramName])
                                    
                                    #Forward only the matching CWE labels across the boundary
                                    currentCalleeScope[paramName].update(activeArgumentCwes)
                                    
                                    #Checks if this pass actually introduced a new unseen vuln label to that param
                                    #If the set size increases, it means a new threat has entered into the callee function
                                    if len(currentCalleeScope[paramName]) > oldLen:
                                        self.activeContexts[calleeFunc].add(calleeCtxID)
                                        changed = True


                    #PASS 2: Pulling return taint from callee back to caller var

                    #Handles exiting a function. It tracks what dirty data successfully escapes through a return statement and contaminates the caller’s local variables.
                    #Handles both unconditional return taints (summary.returnsTainted) and param-dependent returns (summary.taintedReturnParams).
                    #It does an  intersection with what vulns the input parameters actually carried.
                    #If a param carries CWE-78, but the function's return summary says it only leaks CWE-89, the threat is safely blocked from passing back up to the caller var
                    
                    parentStmt = getattr(callSiteInfo, "parentStmt", None)
                    assignedVars = self.getAssignedVarsFromParentStmt(callNode, parentStmt)

                    if not assignedVars and parentStmt is None:
                        fallbackAssignedVar = self.getAssignedVar(callNode, callerFunc)

                        if fallbackAssignedVar:
                            assignedVars = {fallbackAssignedVar}

                    if assignedVars:
                        inheritedReturnCwes = set() #CWE labels the caller’s assigned var receives from the func return value
                        
                        #Unconditional hardcoded source returns inside the callee
                        for cwe, isTainted in summary.returnsTainted.items():
                            if isTainted:
                                inheritedReturnCwes.add(cwe)
                                
                        #Conditional param-dependent returns. funcs that have the potential to be dagerous
                        currentCalleeScope = self.localTaintScopes[(calleeFunc, calleeCtxID)]
                        for pName, returnCweSet in summary.taintedReturnParams.items():
                            if pName in currentCalleeScope:

                                #Set Intersection: Pass label back only if parameter brought that specific hazard
                                activeParamCwes = currentCalleeScope[pName] & returnCweSet
                                inheritedReturnCwes.update(activeParamCwes)

                        if inheritedReturnCwes:
                            for assignedVar in assignedVars:
                                oldLen = len(currentCallerScope[assignedVar])
                                currentCallerScope[assignedVar].update(inheritedReturnCwes)

                                if len(currentCallerScope[assignedVar]) > oldLen:
                                    changed = True



                    #PASS 3: Verifying sinks against the isolated callee context state
                    #It checks if any input parameter that was successfully proved was dirty in Pass 1 ends up crashing directly into a sink inside the function
                    currentCalleeScope = self.localTaintScopes[(calleeFunc, calleeCtxID)]
                    for activeParamName, activeCwes in currentCalleeScope.items():
                        if activeParamName in summary.paramsToSinks:
                            
                            #Pull the nested structural mapping: cwe -> list of sinks reached
                            cweToSinksMap = summary.paramsToSinks[activeParamName]
                            
                            for cwe in activeCwes:
                                if cwe in cweToSinksMap:
                                    sinksHit = cweToSinksMap[cwe]
                                    
                                    for sink in sinksHit:
                                        sig = (callerFunc, callerCtxID, calleeFunc, calleeCtxID, activeParamName, cwe, sink, lineno)
                                        if sig not in reported:
                                            reported.add(sig)
                                            vulnerabilities.append({
                                                "vulnerability": "Cross-File Taint Flow Detected",
                                                "cwe": cwe,
                                                "caller": callerFunc,
                                                "callee": calleeFunc,
                                                "viaParameter": activeParamName,
                                                "sinkReached": sink,
                                                "line": lineno,
                                                "contextId": f"callsiteLine_{calleeCtxID}"
                                            })


        #Since pattern matches and local taints dont flow across files
        #we just pull them straight out of Phase 1
        for summary in self.store._store.values():
            
            #Harvest patternBased Bugs 
            if hasattr(summary, 'bannedPatterns') and summary.bannedPatterns:

                for bug in summary.bannedPatterns:
                    patternSig = ("PATTERN_MATCH", summary.functionName, bug["cwe"], bug["line"], bug["offendingCode"])
                    
                    if patternSig not in reported:
                        reported.add(patternSig)
                        vulnerabilities.append({
                            "vulnerability": bug["vulnerability"],
                            "cwe": bug["cwe"],
                            "caller": "N/A (Static Pattern)",
                            "callee": summary.functionName,
                            "viaParameter": "None",
                            "sinkReached": bug["offendingCode"],
                            "line": bug["line"],
                            "contextId": "global_pattern_match"
                        })

            #Harvest Local Intraprocedural Bugs
            #For funcs where it has 0 params and no return stmt (a.k.a, void function)
            if hasattr(summary, 'localVulnerabilities') and summary.localVulnerabilities:
                for bug in summary.localVulnerabilities:
                    localSig = ("LOCAL_TAINT", summary.functionName, bug["cwe"], bug["line"], bug["sink"])
                    
                    if localSig not in reported:
                        reported.add(localSig)
                        vulnerabilities.append({
                            "vulnerability": bug["vulnerability"],
                            "cwe": bug["cwe"],
                            "caller": summary.functionName,
                            "callee": summary.functionName,
                            "viaParameter": "Local Variable",
                            "sinkReached": bug["sink"],
                            "line": bug["line"],
                            "contextId": "local_taint_flow"
                        })
                                            
        return vulnerabilities