import ast
from vulnai.analysis.intraprocedural.usedef import UseDefAnalyzer
from vulnai.analysis.intraprocedural.reachingdef import ReachingDefinitionAnalyzer
from vulnai.analysis.intraprocedural.cfg import ControlFlowGraph as cfg
from vulnai.analysis.vulnerabilities.vulns import VulnerabilityRule
from vulnai.analysis.interprocedural.summary_and_graph.summarystore import FunctionSummary
from collections import defaultdict
from vulnai.analysis.vulnerabilities.rule_registry import RuleRegistry
from vulnai.analysis.interprocedural.structured_storage.function_info import FunctionInfo

#Follows a guilty until proven innocent path. tainted until proven otherwise

# Local identity info:
# params, decorators, line number, AST node, module, global name
# handled by CodebaseIndexBuilder

# Local behavior info:
# taint flow, returns, sinks, sources, sanitizers, vulnerabilities
# handled by FunctionSummaryBuilder

class FunctionSummaryBuilder:
    def __init__(self, useDefAnalyzer: UseDefAnalyzer, reachingDefAnalyzer: ReachingDefinitionAnalyzer):
        self.uda = useDefAnalyzer
        self.rda = reachingDefAnalyzer

        #Basically says: This var is definitely, unconditionally dangerous rn, and here is the list of specific CWEs why
        #Definition -> set of cwe ids
        self.sourceTaintedMap: dict[object, set[str]] = {} 


        #Basically says: This var is not automatically dangerous on its own.
        #However, its safety depends entirely on what the user passes into the function's parameters.
        #If parameter X arrives at runtime carrying vulnerability Y, this variable will instantly inherit it

        #Definition -> (paramName -> set of cwe ids)
        self.paramTaintedMap: dict[object, dict[str, set[str]]] = {} 

        self.importAliasMap: dict[str, str] = {}



    #Recursively builds fully constructed call path like:
    #input() -> "input"
    #os.system() -> "os.system"
    #xml.etree.ElementTree.fromstring() -> its different parts
    def recursiveGetter(self, node) -> str | None:
            if isinstance(node, ast.Name):
                return node.id
            
            elif isinstance(node, ast.Attribute):

                prefix = self.recursiveGetter(node.value)

                if prefix:
                    return f"{prefix}.{node.attr}"
                return node.attr
            
            return None
    

    #Helper to extract the string name of a call function or method
    def getCallName(self, callNode: ast.Call) -> str | None:
        return self.recursiveGetter(callNode.func)
    

    #Converts all the raw call names we get from getCallName() into the canonical name the rules understand
    #like: sp.Popen -> subprocess.Popen
    def canonicalizeCallName(self, rawCallName: str | None) -> str | None:
        if not rawCallName:
            return None

        if not self.importAliasMap:
            return rawCallName

        parts = rawCallName.split(".")

        firstPart = parts[0]

        if firstPart not in self.importAliasMap:
            return rawCallName

        canonicalFirstPart = self.importAliasMap[firstPart]

        if len(parts) == 1:
            return canonicalFirstPart

        remainingParts = parts[1:]

        return ".".join([canonicalFirstPart] + remainingParts)

    #Tries the canonical call name first, if that finds nothing, try the raw call name
    #Returns both the CWE set and the name that matched
    def lookupCwesForCall(self, rawCallName: str | None, lookupFunc) -> tuple[set[str], str | None]: #str= the matched name from the rule registry
        if not rawCallName:
            return set(), None

        canonicalCallName = self.canonicalizeCallName(rawCallName)

        #Try canonical name first
        if canonicalCallName:
            cwes = lookupFunc(canonicalCallName)
            if cwes:
                return cwes, canonicalCallName

        #Raw fallback
        if rawCallName != canonicalCallName:
            cwes = lookupFunc(rawCallName)
            if cwes:
                return cwes, rawCallName

        return set(), canonicalCallName or rawCallName
    #the set above returns smth like: ({"CWE-78"}, "subprocess.Popen")


    def getSourceCwesForCall(self, rawCallName: str | None, registry: RuleRegistry) -> tuple[set[str], str | None]:
        return self.lookupCwesForCall(rawCallName, registry.getSourceCwes)


    def getSinkCwesForCall(self, rawCallName: str | None, registry: RuleRegistry) -> tuple[set[str], str | None]:
        return self.lookupCwesForCall(rawCallName, registry.getSinkCwes)


    def getSanitizerCwesForCall(self, rawCallName: str | None, registry: RuleRegistry) -> tuple[set[str], str | None]:
        return self.lookupCwesForCall(rawCallName, registry.getSanitizerCwes)


    #checks canonical in rule.sinks, if not there, check raw rule.sinks
    def getMatchedPatternCallName(self, rawCallName: str | None, rule) -> str | None:
        if not rawCallName:
            return None

        canonicalCallName = self.canonicalizeCallName(rawCallName)

        #Try canonical first
        if canonicalCallName and canonicalCallName in rule.sinks:
            return canonicalCallName

        #Raw fallback
        if rawCallName in rule.sinks:
            return rawCallName

        return None

    #Checks if an expression is source tainted and/or does it depend on any function params. Strips the CWE labels off slowly if they do not exist in the function
    #first item it returns is sourceCwes (a set of active source-based CWEs). The second is paramDeps (a dict mapping a param name to the CWEs it could trigger)
    def evaluateExpressionTaint(self, node: ast.AST, params: list[str], registry: RuleRegistry, stmtContext: ast.stmt) -> tuple[set[str], dict[str, set[str]]]:
        if node is None: #no expression, no taint
            return set(), {}

    
        sourceCwes: set[str] = set() #set of cwes that are definitely tainted, like input()
        paramDeps: dict[str, set[str]] = defaultdict(set) #params that have the potential to become tainted

        #is the node a func/method call
        if isinstance(node, ast.Call):
            callName = self.getCallName(node)
            
            #Extract args and the method receiver e.g cmd in cmd.strip(). Treats positional arguments (node.args), keyword argument values (kw.value), and the method receiver object itself (node.func.value) exactly the same.
            argsToCheck = node.args + [kw.value for kw in node.keywords]

            if isinstance(node.func, ast.Attribute):
                argsToCheck.append(node.func.value)


            #loops over all those arguments we just gathered and recursively runs evaluateExpressionTaint on them again, because 
            #we need to ensure that if any sub-component hidden deep inside a nested structure contains a threat,
            #that threat bubbles up and concentrates at the current function call node
            #e.g: execute(a + b), the engine cannot evaluate execute until it knows exactly what a and b are holding
            for argNode in argsToCheck:

                childSrc, childDeps = self.evaluateExpressionTaint(argNode, params, registry, stmtContext)
                sourceCwes.update(childSrc)

                for pName, cwes in childDeps.items():

                    #update because if arg X carries vuln A, and arg Y carries vuln B, a string concat or func wrapper combining them needs both their sinks/sources/sanitizers
                    paramDeps[pName].update(cwes)

            if callName:
                #Sanitizer Set Subtraction. This is where it starts stripping labels off
                sanitizerToCwes, _ = self.getSanitizerCwesForCall(callName, registry)

                if sanitizerToCwes:
                    sourceCwes -= sanitizerToCwes #cleans local var taints

                    for pName in list(paramDeps.keys()):
                        paramDeps[pName] -= sanitizerToCwes #cleans param taints
                        if not paramDeps[pName]:
                            del paramDeps[pName] #Clean up empty dependencies

                #Source Set Addition. handles the case: What if the function call itself is the origin of the toxic data
                #what if a function sanitizes input arguments, but then returns brand new untrusted stuff 
                newSrcCwes, _ = self.getSourceCwesForCall(callName, registry)
                sourceCwes.update(newSrcCwes)

            return sourceCwes, paramDeps

        #is the node a variable
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            incomingDefs = self.uda.useDefEdges.get(stmtContext, {}).get(node.id, set()) #fetches the set of all unique Definition objects that could have given this variable its current value
            

            #loops through every incoming definition obj.
            #It checks if that specific definition was logged inside sourceTaintedMap or paramTaintedMap
            #If an incoming definition is found in the maps,
            #use .update() to pull its active security labels directly into the current node's maps
            #If incDef A carries a Command Injection taint (CWE-78) and incDef B carries a SQL Injection taint (CWE-89), the loop runs twice and executes:
            #sourceCwes = empty set | {"CWE-78"} | {"CWE-89"} = {"CWE-78", CWE-89}
            for incDef in incomingDefs:
                if incDef in self.sourceTaintedMap:
                    sourceCwes.update(self.sourceTaintedMap[incDef])
                    

                if incDef in self.paramTaintedMap:
                    for pName, cwes in self.paramTaintedMap[incDef].items():
                        paramDeps[pName].update(cwes)
                        
            return sourceCwes, paramDeps

        #is the node a constant. Simple return bcz most consts will be safe
        if isinstance(node, ast.Constant):
            return set(), {}

        #If the engine comes across a piece of code that isnt a function call, a var, or a const, it falls through to this block. 
        #It basically dismantles any other Python syntax struct, like binary operations (x + y), lists ([a, b, c]),
        #or dicts and forces the taint analysis to go deeper
        for field, value in ast.iter_fields(node):

            #Checks if this is a list of child AST components. if we have a list, elts would be the field, and the child node will be the value, (elt can hold a list of ast nodes, so this will confirm if it is a child node or not)
            if isinstance(value, list):

                for item in value:

                    if isinstance(item, ast.AST):

                        childSrc, childDeps = self.evaluateExpressionTaint(item, params, registry, stmtContext)
                        sourceCwes.update(childSrc)

                        for pName, cwes in childDeps.items():
                            paramDeps[pName].update(cwes)

            #handles child nodes that are not iterables
            elif isinstance(value, ast.AST):
                childSrc, childDeps = self.evaluateExpressionTaint(value, params, registry, stmtContext)
                sourceCwes.update(childSrc)

                for pName, cwes in childDeps.items():
                    paramDeps[pName].update(cwes)

        return sourceCwes, paramDeps
    

    #Handles pattern based taints like hardcoded vals
    def checkPatternBased(self, stmt: ast.stmt, registry: RuleRegistry, summary: FunctionSummary) -> None:
        lineno = getattr(stmt, 'lineno', "Unknown")

        for node in ast.walk(stmt):

            #BANNED CALL PATTERNS e.g, eval()
            if isinstance(node, ast.Call):
                callName = self.getCallName(node)
                if callName:

                    for rule in registry.patternRules:
                        matchedCallName = self.getMatchedPatternCallName(callName, rule)

                        if matchedCallName:
                            summary.bannedPatterns.append({
                                "vulnerability": f"Static Pattern Match: {rule.name}",
                                "cwe": rule.cwe,
                                "offendingCode": ast.unparse(stmt).strip(),
                                "line": lineno
                            })

            #BANNED ASSIG PATTERNS e.g. API_KEY = "1234"
            elif isinstance(stmt, ast.Assign):
                isSecretVar = False
                for target in stmt.targets:

                    if isinstance(target, ast.Name):

                        for rule in registry.patternRules:

                            if target.id in rule.sinks:
                                isSecretVar = True

                    elif isinstance(target, ast.Attribute):
                        for rule in registry.patternRules:

                            if target.attr in rule.sinks:
                                isSecretVar = True
                
                if isSecretVar:

                    if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                        for rule in registry.patternRules:
                            summary.bannedPatterns.append({
                                "vulnerability": f"Static Pattern Match: {rule.name}",
                                "cwe": rule.cwe,
                                "offendingCode": ast.unparse(stmt).strip(),
                                "line": lineno
                            })

                        break



    #Take one function -> Analyze it locally -> Return a FunctionSummary
    #I wanted to modularize this more, but i am genuinely too scared and too tired to try, so bear with the block of code lol
    def buildSummary(self, funcInfo: FunctionInfo, cfgObj: cfg, registry: RuleRegistry, importAliasMap: dict[str, str]):

        #track the srcs and params for the func being checked ONLY
        self.sourceTaintedMap = {}
        self.paramTaintedMap = defaultdict(lambda: defaultdict(set))
        self.importAliasMap = importAliasMap

        fullName = funcInfo.globalName

        summary = FunctionSummary(functionName=fullName)

        
        #A param is an untrusted entry whose contents are unknown during Phase 1.
        #By stamping the param with every possible CWE label up front,
        #the engine can trace those labels through the function's internal syntax branches.
        #If an input travels through an HTML sanitizer, the XSS label drops off. Labels keep dropping off and whatever
        #labels survive to the end, are recorded.
        params = funcInfo.params
        allCwes = {rule.cwe for rule in registry.taintRules} #list of all cwes from rule registry

        for block in cfgObj.blocks:

            for stmt in block.statements:
                
                self.checkPatternBased(stmt, registry, summary)

                #get the Def obj from the lookup table for the params
                if isinstance(stmt, ast.arguments) and stmt in self.rda.definitionLookup:
                    for pName in self.rda.definitionLookup[stmt]:

                        if pName in params:
                            pDef = self.rda.definitionLookup[stmt][pName]
                            self.paramTaintedMap[pDef][pName] = set(allCwes) #the Def gets marked tainted at this point


        #Fixed point iteration...(yes again, lol)
        changed = True
        while changed:
            changed = False 

            for block in cfgObj.blocks:
                for stmt in block.statements:
                    if isinstance(stmt, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                        createdDefs = []

                        if stmt in self.rda.definitionLookup:
                            for varName in self.rda.definitionLookup[stmt]:
                                createdDefs.append(self.rda.definitionLookup[stmt][varName])

                        #Extracts the right-hand side (RHS) expression node
                        rhsNode = stmt.value if hasattr(stmt, 'value') and stmt.value is not None else None

                        #for aug assign like +=, -= etc
                        if not rhsNode and isinstance(stmt, ast.AugAssign):
                            rhsNode = stmt.value

                        #for ann assign, eg x: int
                        if not rhsNode:
                            continue

                        #extracts all the vulns in the RHS, since the LHs depends on them
                        sourceCwes, paramDeps = self.evaluateExpressionTaint(rhsNode, params, registry, stmt)

                        #check the LHS
                        for defi in createdDefs:

                            #says: Did the right-hand side of this assignment actually contain any active vulnerability labels
                            #if yes, then the val being assigned to the variable is tainted,
                            #so we need to register its definition into the src taint map
                            if sourceCwes: #Checks if the expression on the rhs contained a source
                                if defi not in self.sourceTaintedMap:
                                    self.sourceTaintedMap[defi] = set()


                                #prevents infinite loops. rule regitry has a limited number of rules, so once that number is met. it means we tracked everything possible. this is for the loop exit
                                oldLen = len(self.sourceTaintedMap[defi])
                                self.sourceTaintedMap[defi].update(sourceCwes)

                                if len(self.sourceTaintedMap[defi]) > oldLen:
                                    changed = True

                            if paramDeps: #Checvks if the expr in the RHS came from the parameter
                                for pName, cwes in paramDeps.items():
                                    oldLen = len(self.paramTaintedMap[defi][pName])
                                    self.paramTaintedMap[defi][pName].update(cwes)


                                    if len(self.paramTaintedMap[defi][pName]) > oldLen:
                                        changed = True


        #Handles the return value scan
        #scans the Return statements of the function to see if exiting data carries direct threats or depends on params
        #this is imp bcz what if something returns a non-var expr like return html.escape(X), need to catch that
        for block in cfgObj.blocks:
            for stmt in block.statements:

                if isinstance(stmt, ast.Return) and stmt.value:
                    sourceCwes, paramDeps = self.evaluateExpressionTaint(stmt.value, params, registry, stmt)
                    
                    for cwe in sourceCwes:
                        summary.returnsTainted[cwe] = True #flags that whatever params you pass in the func, it will ALWAYS return tainted data 

                        if isinstance(stmt.value, ast.Call):
                            callName = self.getCallName(stmt.value)

                            directSourceCwes, matchedSourceName = self.getSourceCwesForCall(callName, registry)

                            if matchedSourceName and cwe in directSourceCwes:
                                summary.directSourceReturn[cwe] = matchedSourceName

                    #Checks if the parameter name has been seen yet in our summary map (initializing it with an empty set if it's new),
                    #and runs .update(cwes) to merge the vulnerability labels
                    #This prevents the scenario that if a caller passes a variable contaminated with CWE-X into the param, that exact CWE threat will survive
                    for pName, cwes in paramDeps.items():

                        if pName not in summary.taintedReturnParams:
                            summary.taintedReturnParams[pName] = set()

                        summary.taintedReturnParams[pName].update(cwes)


        #Scans the sinks
        #Handles two types of findings:
        #Local Bugs: Vulns contained within this single funct
        #Cross-File Bridges: Potential vulns that can be triggered externally via func params
        for block in cfgObj.blocks:

            for stmt in block.statements:

                for node in ast.walk(stmt):

                    if isinstance(node, ast.Call):
                        callName = self.getCallName(node)
                        sinkCwes, matchedSinkName = self.getSinkCwesForCall(callName, registry)
                        
                        if matchedSinkName and sinkCwes:
                            if matchedSinkName not in summary.sinkCalls:
                                summary.sinkCalls.append(matchedSinkName)

                            argsToCheck = node.args + [kw.value for kw in node.keywords]
                            
                            for argNode in argsToCheck:
                                sourceCwes, paramDeps = self.evaluateExpressionTaint(argNode, params, registry, stmt)
                                
                                #handles the scenario where an explicit source hits a sink completely LOCALLY in the func e.g os.system(input())
                                activeSinkCwes = sourceCwes & sinkCwes #Identify vulns by finding where the arg's taints (sourceCwes) match the funct's sinks (sinkCwes). if they both have the same cwes, it means vulnerability has basically been confirmed

                                for cwe in activeSinkCwes:

                                    localSig = (fullName, cwe, matchedSinkName, ast.unparse(argNode).strip(), getattr(stmt, 'lineno', 0))

                                    if localSig not in summary._reportedLocalSigs:
                                        summary._reportedLocalSigs.add(localSig)
                                        summary.localVulnerabilities.append({
                                            "vulnerability": "Local Taint-To-Sink Flow",
                                            "cwe": cwe,
                                            "sink": matchedSinkName,
                                            "expression": ast.unparse(node).strip(),
                                            "line": getattr(stmt, 'lineno', "Unknown")
                                        })

                                #handles CROSS-FILE conditional exploits. like a vuln can be in a function, and a specific file can trigger it via the param
                                #If an attacker can control param W, they can trigger vuln X inside the dangerous func Y later on.
                                for pName, cwes in paramDeps.items():
                                    activeParamCwes = cwes & sinkCwes

                                    for cwe in activeParamCwes:
                                        if pName not in summary.paramsToSinks:
                                            summary.paramsToSinks[pName] = defaultdict(list)

                                        if matchedSinkName not in summary.paramsToSinks[pName][cwe]:
                                            summary.paramsToSinks[pName][cwe].append(matchedSinkName)

        return summary