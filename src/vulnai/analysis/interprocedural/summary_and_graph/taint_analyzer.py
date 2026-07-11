import ast
from collections import defaultdict
from vulnai.analysis.interprocedural.code_graph.graph import CodeGraph
from vulnai.analysis.interprocedural.summary_and_graph.summarystore import SummaryStore
from vulnai.analysis.vulnerabilities.rule_registry import RuleRegistry

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
    def __init__(self, store: SummaryStore, functionParamMap: dict[str, list[str]], functionAstMap: dict[str, ast.FunctionDef], registry: RuleRegistry | None):
        self.store = store #contains all func summaries
        self.functionParamMap = functionParamMap #func name -> params
        self.functionAstMap = functionAstMap #func name -> AST node
        self.registry = registry

        #(function name, context id) -> varName -> set of active CWE ids
        self.localTaintScopes: dict[tuple[str, int], dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
        
        #function names -> a set of their currently active context IDs
        self.activeContexts: dict[str, set[int]] = defaultdict(set)
        self.contextInit()
        self.seedBaseContextsFromSummaries()

        #(functionName, contextId) -> earliest line where returned taint entered that function context
        self.contextsNeedingSinkReplay: dict[tuple[str, int], int] = {}


    #Inits all known functions with a base root context id (which is 0)
    def contextInit(self) -> None:
        for funcName in self.functionParamMap.keys():
            self.activeContexts[funcName].add(0)

    #takes local source facts discovered by FunctionSummaryBuilder and loads them into the interprocedural analyzer
    def seedBaseContextsFromSummaries(self) -> None:
        for summary in self.store._store.values():
            scope = self.localTaintScopes[(summary.functionName, 0)]
            for varName, cwes in getattr(summary, "localSourceVars", {}).items():
                scope[varName].update(cwes)


    def recursiveGetter(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        
        elif isinstance(node, ast.Call):
                return self.recursiveGetter(node.func)
        if isinstance(node, ast.Attribute):
            prefix = self.recursiveGetter(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return None

    #Normalizes subscript keys to match FunctionSummaryBuilder.
    def subscriptKey(self, node: ast.AST | None) -> str | None:
       
        if node is None:
            return None

        if isinstance(node, ast.Constant):
            return repr(node.value)

        try:
            return ast.unparse(node).strip()
        except Exception:
            return None

    #Builds stable names for replay-time access-path lookups.
    def accessPath(self, node: ast.AST | None) -> str | None:
      
        if node is None:
            return None

        if isinstance(node, ast.Name):
            return node.id

        if isinstance(node, ast.Attribute):
            prefix = self.accessPath(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr

        if isinstance(node, ast.Subscript):
            base = self.accessPath(node.value)
            key = self.subscriptKey(node.slice)

            if base and key:
                return f"{base}[{key}]"

        return None


    def getCallName(self, callNode: ast.Call) -> str | None:
        return self.recursiveGetter(callNode.func)

    # Keeps replay-time SQLi focused on the SQL/query expression.
    # Bound parameters should not be treated as injected SQL text.
    def relevantSinkArgs(self, callNode: ast.Call, sinkName: str, sinkCwes: set[str]) -> list[ast.AST]:
        if "CWE-89" in sinkCwes and (
            sinkName.endswith(".execute")
            or sinkName.endswith(".executemany")
            or sinkName in {"execute", "executemany", "executescript"}
        ):
            relevantArgs = []

            if callNode.args:
                relevantArgs.append(callNode.args[0])

            for kw in callNode.keywords:
                if kw.arg in {"sql", "query", "statement"}:
                    relevantArgs.append(kw.value)

            return relevantArgs

        argsToCheck = list(callNode.args) + [kw.value for kw in callNode.keywords]

        if isinstance(callNode.func, ast.Attribute):
            argsToCheck.append(callNode.func.value)

        return argsToCheck

    # Finds parser variables that explicitly enable XML externals.
    # Replay can then suppress parseString(..., safe_parser) XXE false positives.
    def unsafeXmlParsersInFunction(self, funcAst: ast.AST) -> set[str]:
        unsafeParsers = set()

        for node in ast.walk(funcAst):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue

            if node.func.attr != "setFeature" or len(node.args) < 2:
                continue

            enabledArg = node.args[1]
            if not (isinstance(enabledArg, ast.Constant) and enabledArg.value is True):
                continue

            featureText = ast.unparse(node.args[0]).lower()
            if "external" not in featureText:
                continue

            parserName = self.accessPath(node.func.value)
            if parserName:
                unsafeParsers.add(parserName)

        return unsafeParsers

    #  Applies safe XML/YAML sink shapes during replay.
    def refineReplaySinkCwes(self, callNode: ast.Call, sinkName: str | None, sinkCwes: set[str], funcAst: ast.AST) -> set[str]:
        refined = set(sinkCwes)

        if not sinkName:
            return refined

        if "CWE-611" in refined and sinkName in {"xml.dom.minidom.parseString", "parseString"} and len(callNode.args) >= 2:
            parserName = self.accessPath(callNode.args[1])
            unsafeParsers = self.unsafeXmlParsersInFunction(funcAst)

            if parserName and parserName not in unsafeParsers:
                refined.discard("CWE-611")

        if "CWE-502" in refined and sinkName in {"yaml.safe_load", "safe_load"}:
            refined.discard("CWE-502")

        if "CWE-502" in refined and sinkName in {"yaml.load", "ruamel.yaml.YAML.load", "load"}:
            for kw in callNode.keywords:
                if kw.arg == "Loader":
                    loaderName = self.accessPath(kw.value) or self.recursiveGetter(kw.value) or ""
                    if loaderName.endswith("SafeLoader") or loaderName.endswith("CSafeLoader"):
                        refined.discard("CWE-502")

            if len(callNode.args) >= 2:
                loaderName = self.accessPath(callNode.args[1]) or self.recursiveGetter(callNode.args[1]) or ""
                if loaderName.endswith("SafeLoader") or loaderName.endswith("CSafeLoader"):
                    refined.discard("CWE-502")

        return refined


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

    #extracts variable names from assignment targets
    def extractAssignedNames(self, target: ast.AST) -> set[str]:
        assignedNames = set()

        #Return captures can land in access paths
        #Example: holder.value = helper() records holder.value, not just names
        targetPath = self.accessPath(target)

        if targetPath:
            assignedNames.add(targetPath)

        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                assignedNames.update(self.extractAssignedNames(elt))

        return assignedNames


    #answers: Given a function call, which variable or variables receive the return value of that call
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


    #Given an expression and the current caller scope, what CWE taint labels does this expression carry?
    #scope is: expr -> set of cews it may have
    def evaluateExpressionCwes(self, node: ast.AST | None, scope: dict[str, set[str]]) -> set[str]:
        if node is None:
            return set()

        if isinstance(node, ast.Name):
            # Names can inherit container-wide taint from name[*].
            # This supports list append/pop/join flows during replay.
            cwes = set(scope.get(node.id, set()))
            cwes.update(scope.get(f"{node.id}[*]", set()))
            return cwes

        if isinstance(node, ast.Constant):
            return set()

        cwes = set()

        if isinstance(node, ast.Call):
            callName = self.getCallName(node)

            argsToCheck = list(node.args) + [kw.value for kw in node.keywords] #gathers positional and keyword argument exprs
            if isinstance(node.func, ast.Attribute):
                argsToCheck.append(node.func.value)

            for child in argsToCheck:
                cwes.update(self.evaluateExpressionCwes(child, scope))

            #If the call is a sanitizer, remove those CWE labels
            if self.registry and callName:
                sanitizerCwes = self.registry.getSanitizerCwes(callName)
                if sanitizerCwes:
                    cwes -= sanitizerCwes

                sourceCwes = self.registry.getSourceCwes(callName)
                cwes.update(sourceCwes)

            return cwes

        if isinstance(node, ast.Subscript):

            #Replays taint through subscript reads
            #This reads scope facts exported as data['key'] by summaries
            fullName = self.accessPath(node)

            if fullName:
                cwes.update(scope.get(fullName, set()))
                # Subscript reads fall back to container-wide taint.
                # This mirrors FunctionSummaryBuilder.loadSymbolTaint().
                cwes.update(scope.get(fullName.split("[", 1)[0] + "[*]", set()))

            cwes.update(self.evaluateExpressionCwes(node.value, scope))
            return cwes

        if isinstance(node, ast.Attribute):

            #Attribute replay uses accessPath-compatible names.
            #This keeps holder.value aligned with summary localSourceVars
            fullName = self.accessPath(node)

            if fullName:
                cwes.update(scope.get(fullName, set()))

                if self.registry:
                    sanitizerCwes = self.registry.getSanitizerCwes(fullName)
                    if sanitizerCwes:
                        cwes -= sanitizerCwes

                    sourceCwes = self.registry.getSourceCwes(fullName)
                    cwes.update(sourceCwes)

            cwes.update(self.evaluateExpressionCwes(node.value, scope))
            return cwes
        

        #If the expr is not a simple name, constant, call, or attribute, this recursively explores its fields
        for _, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        cwes.update(self.evaluateExpressionCwes(item, scope))
            elif isinstance(value, ast.AST):
                cwes.update(self.evaluateExpressionCwes(value, scope))

        return cwes


    #maps call arguments to callee parameters with taint labels
    def bindArgumentCwes(self, callNode: ast.Call, calleeParamNames: list[str], currentCallerScope: dict[str, set[str]]) -> dict[str, set[str]]:
        bound = defaultdict(set) #param name -> set of cwe ids

        for argPos, argNode in enumerate(callNode.args):
            if argPos < len(calleeParamNames):
                paramName = calleeParamNames[argPos]
            elif calleeParamNames:
                paramName = calleeParamNames[-1]
            else:
                continue

            bound[paramName].update(self.evaluateExpressionCwes(argNode, currentCallerScope))

        for kw in callNode.keywords:
            if kw.arg and kw.arg in calleeParamNames:
                bound[kw.arg].update(self.evaluateExpressionCwes(kw.value, currentCallerScope))
            elif kw.arg is None and calleeParamNames:
                bound[calleeParamNames[-1]].update(self.evaluateExpressionCwes(kw.value, currentCallerScope))

        return bound

    #returns all ast.Call nodes that belong to the current function body but not nested functions/classes/lambdas
    def iterCallsInCurrentFunction(self, funcNode: ast.AST) -> list[ast.Call]:
        calls: list[ast.Call] = []

        class Visitor(ast.NodeVisitor):
            def __init__(self, root):
                self.root = root

            #If the function definition is the root function, walk inside it otherwise skip
            def visit_FunctionDef(self, node):
                if node is self.root:
                    self.generic_visit(node)

            #If the async function definition is the root function, walk inside it otherwise skip
            def visit_AsyncFunctionDef(self, node):
                if node is self.root:
                    self.generic_visit(node)

            #When reaching a class definition, do not walk into its children
            def visit_ClassDef(self, node):
                return

            def visit_Lambda(self, node):
                return

            def visit_Call(self, node):
                calls.append(node)
                self.generic_visit(node)

        Visitor(funcNode).visit(funcNode)
        return calls

    def replayLocalSinksAfterInterproceduralTaint(self, reported: set) -> list[dict]:
        vulnerabilities = []

        if not self.registry:
            return vulnerabilities

        for (funcName, ctxID), minLine in self.contextsNeedingSinkReplay.items():
            funcAst = self.functionAstMap.get(funcName)

            if not funcAst:
                continue

            currentScope = self.localTaintScopes[(funcName, ctxID)]

            if not currentScope:
                continue

            for callNode in self.iterCallsInCurrentFunction(funcAst):
                callLine = getattr(callNode, "lineno", 0)

                if callLine and minLine and callLine < minLine:
                    continue

                callName = self.getCallName(callNode)
                sinkCwes = self.registry.getSinkCwes(callName)
                sinkCwes = self.refineReplaySinkCwes(callNode, callName, sinkCwes, funcAst)

                if not callName or not sinkCwes:
                    continue

                # Replay uses CWE-aware relevant sink args.
                # This keeps interprocedural SQL params from becoming false positives.
                argsToCheck = self.relevantSinkArgs(callNode, callName, sinkCwes)

                for argNode in argsToCheck:
                    activeCwes = self.evaluateExpressionCwes(argNode, currentScope) & sinkCwes

                    for cwe in activeCwes:
                        sig = (
                            "INTERPROCEDURAL_REPLAY",
                            funcName,
                            ctxID,
                            cwe,
                            callName,
                            callLine,
                            ast.unparse(argNode).strip(),
                        )

                        if sig in reported:
                            continue

                        reported.add(sig)
                        vulnerabilities.append({
                            "vulnerability": "Interprocedural Returned Taint-To-Sink Flow",
                            "cwe": cwe,
                            "caller": funcName,
                            "callee": funcName,
                            "viaParameter": "Returned/Propagated Local Value",
                            "sinkReached": callName,
                            "line": callLine,
                            "contextId": f"interprocedural_replay_{ctxID}",
                        })

        return vulnerabilities

    #runs the global fixed-point taint propagation over the call graph
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
                    boundArgs = self.bindArgumentCwes(callNode, calleeParamNames, currentCallerScope)

                    #PASS 1: Shifting taint from caller args to callee params
                    #This pass handles ENTERING a function. It checks the variables passing INTO a val
                    for paramName, activeArgumentCwes in boundArgs.items():

                        #Verifies that the caller isn't passing more positional args than the func's definition supports
                        #If it matches a valid index, it maps that index straight to the param string name (paramName)
                        if not activeArgumentCwes:
                            continue
                            
                        #Check taint status inside the caller's execution context
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

                    if not assignedVars and parentStmt is None and hasattr(self, "getAssignedVar"):
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
                                    replayKey = (callerFunc, callerCtxID)
                                    oldReplayLine = self.contextsNeedingSinkReplay.get(replayKey)

                                    if oldReplayLine is None or lineno < oldReplayLine:
                                        self.contextsNeedingSinkReplay[replayKey] = lineno

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

        for bug in self.replayLocalSinksAfterInterproceduralTaint(reported):
            vulnerabilities.append(bug)

        
        #Since pattern matches and local taints dont flow across files
        #we just pull them straight out of Phase 1
        for summary in self.store._store.values():
            
            #Harvest patternBased Bugs 
            if hasattr(summary, 'bannedPatterns') and summary.bannedPatterns:

                for bug in summary.bannedPatterns:
                    offendingCode = bug.get("offendingCode", bug.get("sink", ""))
                    patternSig = ("PATTERN_MATCH", summary.functionName, bug["cwe"], bug["line"], offendingCode)
                    
                    if patternSig not in reported:
                        reported.add(patternSig)
                        vulnerabilities.append({
                            "vulnerability": bug["vulnerability"],
                            "cwe": bug["cwe"],
                            "caller": "N/A (Static Pattern)",
                            "callee": summary.functionName,
                            "viaParameter": "None",
                            "sinkReached": offendingCode,
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
