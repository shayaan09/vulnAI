import ast
from vulnai.analysis.intraprocedural.usedef import UseDefAnalyzer
from vulnai.analysis.intraprocedural.reachingdef import ReachingDefinitionAnalyzer
from vulnai.analysis.intraprocedural.cfg import ControlFlowGraph as cfg
from vulnai.analysis.vulnerabilities.vulns import VulnerabilityRule
from vulnai.analysis.interprocedural.summary_and_graph.summarystore import FunctionSummary
from collections import defaultdict
from vulnai.analysis.vulnerabilities.rule_registry import RuleRegistry
from vulnai.analysis.interprocedural.structured_storage.function_info import FunctionInfo
import operator

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

        #tracks taint on access paths like obj.attr or data['key']
        self.symbolSourceTaintMap: dict[str, set[str]] = {}
        self.symbolParamTaintMap: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))

        self.importAliasMap: dict[str, str] = {}

        #Records local parser/path facts that change CWE-specific reporting.
        self.unsafeXmlParserVars: set[str] = set()
        self.pathValidatedVars: set[str] = set()

        #Tracks simple local constants for branch precision.
        self.constantValueMap: dict[str, object] = {}



    #Recursively builds fully constructed call path like:
    #input() -> "input"
    #os.system() -> "os.system"
    #xml.etree.ElementTree.fromstring() -> its different parts
    def recursiveGetter(self, node) -> str | None:
            if isinstance(node, ast.Name):
                return node.id

            elif isinstance(node, ast.Call):
                return self.recursiveGetter(node.func)
            
            elif isinstance(node, ast.Attribute):

                prefix = self.recursiveGetter(node.value)

                if prefix:
                    return f"{prefix}.{node.attr}"
                return node.attr
            
            return None
    

    #Helper to extract the string name of a call function or method
    def getCallName(self, callNode: ast.Call) -> str | None:
        return self.recursiveGetter(callNode.func)

    #Normalizes literal subscript keys for access-path tracking.
    #Eg: data["id"] becomes data['id'] consistently.
    def subscriptKey(self, node: ast.AST | None) -> str | None:
        if node is None:
            return None

        if isinstance(node, ast.Constant):
            return repr(node.value)

        try:
            return ast.unparse(node).strip()
        except Exception:
            return None

    #Builds a stable name for Name/Attribute/Subscript locations
    #This lets taint survive through dicts, object fields, and config maps
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

    #Extracts assignment targets beyond plain names
    #Eg: x, obj.field, data['key'], and tuple/list destructuring.
    def getAssignedAccessPaths(self, stmt: ast.stmt) -> list[str]:
        targets: list[ast.AST] = []

        if isinstance(stmt, ast.Assign):
            targets = list(stmt.targets)
        elif isinstance(stmt, ast.AnnAssign):
            targets = [stmt.target]
        elif isinstance(stmt, ast.AugAssign):
            targets = [stmt.target]

        assignedPaths: list[str] = []

        def collect(target: ast.AST) -> None:
            if isinstance(target, (ast.Tuple, ast.List)):
                for elt in target.elts:
                    collect(elt)
                return

            path = self.accessPath(target)
            if path:
                assignedPaths.append(path)

        for target in targets:
            collect(target)

        return assignedPaths

    #Merges param dependency maps and reports whether anything grew
    #Fixed-point loops will use this to know when access-path taint changed
    def mergeParamDeps(self, dest: dict[str, set[str]], src: dict[str, set[str]]) -> bool:
       
        changed = False

        for pName, cwes in src.items():
            oldLen = len(dest[pName])
            dest[pName].update(cwes)

            if len(dest[pName]) > oldLen:
                changed = True

        return changed

    #Records taint for access paths independent of RDA Definition objects
    #This is what makes data['k'] and holder.value behave like taintable vars
    def recordSymbolTaint(self, symbol: str, sourceCwes: set[str], paramDeps: dict[str, set[str]]) -> bool:
        changed = False

        if sourceCwes:
            if symbol not in self.symbolSourceTaintMap:
                self.symbolSourceTaintMap[symbol] = set()

            oldLen = len(self.symbolSourceTaintMap[symbol])
            self.symbolSourceTaintMap[symbol].update(sourceCwes)

            if len(self.symbolSourceTaintMap[symbol]) > oldLen:
                changed = True

        if paramDeps:
            if self.mergeParamDeps(self.symbolParamTaintMap[symbol], paramDeps):
                changed = True

       
        return False

    #Clears access-path taint when a symbol is overwritten safely
    def clearSymbolTaint(self, symbol: str) -> bool:
        changed = False

        if symbol in self.symbolSourceTaintMap:
            del self.symbolSourceTaintMap[symbol]
            changed = True

        if symbol in self.symbolParamTaintMap:
            del self.symbolParamTaintMap[symbol]
            changed = True

        
        return False

    #Reads taint previously stored for an access path
    #Returns source CWEs and param-dependent CWEs in the same shape as expression eval
    def loadSymbolTaint(self, symbol: str) -> tuple[set[str], dict[str, set[str]]]:
       
        sourceCwes = set(self.symbolSourceTaintMap.get(symbol, set()))
        paramDeps: dict[str, set[str]] = defaultdict(set)

        for pName, cwes in self.symbolParamTaintMap.get(symbol, {}).items():
            paramDeps[pName].update(cwes)

        #Falls back from exact indexes to container-wide taint.
        #This lets list append/pop flows reach reads like items[0] or items.pop().
        wildcardSymbol = None
        if "[" in symbol:
            wildcardSymbol = symbol.split("[", 1)[0] + "[*]"
        else:
            wildcardSymbol = f"{symbol}[*]"

        if wildcardSymbol != symbol:
            sourceCwes.update(self.symbolSourceTaintMap.get(wildcardSymbol, set()))

            for pName, cwes in self.symbolParamTaintMap.get(wildcardSymbol, {}).items():
                paramDeps[pName].update(cwes)

        return sourceCwes, paramDeps

    #Models map/config-style get calls as reads from stored access paths
    #Eg: conf.get('s','k') and data.get('k') become stable symbols.
    def configGetPathFromCall(self, callNode: ast.Call) -> str | None:        
        if not isinstance(callNode.func, ast.Attribute):
            return None

        if callNode.func.attr != "get":
            return None

        receiver = self.accessPath(callNode.func.value)
        if not receiver or not callNode.args:
            return None

        firstKey = self.subscriptKey(callNode.args[0])
        if not firstKey:
            return None

        if len(callNode.args) >= 2:
            secondKey = self.subscriptKey(callNode.args[1])

            if secondKey:
                return f"{receiver}[{firstKey}][{secondKey}]"

        return f"{receiver}[{firstKey}]"

    #Models ConfigParser-style set calls as writes to access paths
    #Eg: conf.set('s','k', value) stores taint at conf['s']['k']
    def configSetTargetFromCall(self, callNode: ast.Call) -> tuple[str | None, ast.AST | None]:
        if not isinstance(callNode.func, ast.Attribute):
            return None, None

        if callNode.func.attr != "set":
            return None, None

        receiver = self.accessPath(callNode.func.value)
        if not receiver or len(callNode.args) < 3:
            return None, None

        sectionKey = self.subscriptKey(callNode.args[0])
        itemKey = self.subscriptKey(callNode.args[1])

        if not sectionKey or not itemKey:
            return None, None

        return f"{receiver}[{sectionKey}][{itemKey}]", callNode.args[2]

    #Detects framework route handlers from decorator text.
    #Route returns can be browser-rendered sinks for reflected XSS.
    def isRouteHandler(self, funcInfo: FunctionInfo) -> bool:
        for decorator in getattr(funcInfo, "decorators", []):
            if ".route(" in decorator or decorator.startswith("route("):
                return True

        return False

    #Uses route/decorator names as a weak HTML-context signal.
    #OWASP names XSS routes explicitly; real apps still need body/HTML evidence below.
    def routeHasXssHint(self, funcInfo: FunctionInfo) -> bool:
        for decorator in getattr(funcInfo, "decorators", []):
            lowered = decorator.lower()
            if "xss" in lowered or "cross-site" in lowered:
                return True

        return False

    #Pulls the browser-rendered body out of response constructors.
    # Header-only taint in make_response/json/redirect should not become XSS.
    def routeReturnBodyExpr(self, node: ast.AST) -> ast.AST | None:
        if not isinstance(node, ast.Call):
            return node

        callName = self.canonicalizeCallName(self.getCallName(node)) or self.getCallName(node)
        safeResponseCalls = {
            "flask.redirect",
            "redirect",
            "url_for",
            "flask.jsonify",
            "jsonify",
            "JsonResponse",
            "django.http.JsonResponse",
            "send_file",
            "flask.send_file",
            "send_from_directory",
            "flask.send_from_directory",
        }

        if callName in safeResponseCalls:
            return None

        if callName in {"make_response", "flask.make_response", "Response", "flask.Response"}:
            if not node.args:
                return None

            body = node.args[0]
            if isinstance(body, ast.Tuple) and body.elts:
                return body.elts[0]

            return body

        return node

    #Distinguishes generic reflected text from stronger HTML/XSS evidence.
    #This keeps OWASP XSS coverage while reducing route_return pollution elsewhere.
    def routeReturnHasXssEvidence(self, node: ast.AST, funcInfo: FunctionInfo) -> bool:
        if self.routeHasXssHint(funcInfo):
            return True

        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                text = child.value.lower()
                if "<" in text or "&lt;" in text or "text/html" in text:
                    return True

            if isinstance(child, ast.Call):
                callName = self.canonicalizeCallName(self.getCallName(child)) or self.getCallName(child)
                if callName in {
                    "render_template_string",
                    "flask.render_template_string",
                    "HTMLResponse",
                    "starlette.responses.HTMLResponse",
                    "fastapi.responses.HTMLResponse",
                }:
                    return True

        return False

    #Keeps SQLi focused on the query expression, not bound params.
    #DB-API placeholders make tainted second arguments safe for SQLi.
    def relevantSinkArgs(self, callNode: ast.Call, matchedSinkName: str, sinkCwes: set[str]) -> list[ast.AST]:
        if "CWE-89" in sinkCwes and (
            matchedSinkName.endswith(".execute")
            or matchedSinkName.endswith(".executemany")
            or matchedSinkName in {"execute", "executemany", "executescript"}
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

    # Suppresses XXE when minidom.parseString receives a parser
    # that was not configured to enable external entities in the same function.
    def isSafeXxeCall(self, callNode: ast.Call, matchedSinkName: str) -> bool:
        if matchedSinkName not in {"xml.dom.minidom.parseString", "parseString"}:
            return False

        if len(callNode.args) < 2:
            return False

        parserName = self.accessPath(callNode.args[1])
        return bool(parserName and parserName not in self.unsafeXmlParserVars)

    #Treats yaml.safe_load and SafeLoader-shaped yaml.load as safe.
    # Unsafe loaders remain reportable because they can construct Python objects.
    def isSafeDeserializationCall(self, callNode: ast.Call, matchedSinkName: str) -> bool:
        if matchedSinkName in {"yaml.safe_load", "safe_load"}:
            return True

        if matchedSinkName not in {"yaml.load", "ruamel.yaml.YAML.load", "load"}:
            return False

        for kw in callNode.keywords:
            if kw.arg == "Loader":
                loaderName = self.accessPath(kw.value) or self.recursiveGetter(kw.value) or ""
                if loaderName.endswith("SafeLoader") or loaderName.endswith("CSafeLoader"):
                    return True

        if len(callNode.args) >= 2:
            loaderName = self.accessPath(callNode.args[1]) or self.recursiveGetter(callNode.args[1]) or ""
            if loaderName.endswith("SafeLoader") or loaderName.endswith("CSafeLoader"):
                return True

        return False

    #Removes CWE labels when a call shape is known safe for that CWE.
    # This is the precision gate between broad source/sink coverage and final reports.
    def refineSinkCwesForCall(self, callNode: ast.Call, matchedSinkName: str | None, sinkCwes: set[str]) -> set[str]:
        refined = set(sinkCwes)

        if not matchedSinkName:
            return refined

        if "CWE-611" in refined and self.isSafeXxeCall(callNode, matchedSinkName):
            refined.discard("CWE-611")

        if "CWE-502" in refined and self.isSafeDeserializationCall(callNode, matchedSinkName):
            refined.discard("CWE-502")

        return refined

    # Detects parser.setFeature(..., True) as unsafe XXE configuration.
    # Later parseString(..., parser) calls stay reportable only for these parser vars.
    def recordXmlParserConfig(self, stmt: ast.stmt) -> None:
        for node in ast.walk(stmt):
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
                self.unsafeXmlParserVars.add(parserName)

    #  Detects simple denylist-return path validation guards.
    # A guard like if "../" in path: return removes CWE-22 for that variable.
    def recordPathValidationFacts(self, stmt: ast.stmt) -> None:
        if not isinstance(stmt, ast.If):
            return

        if not any(isinstance(child, ast.Return) for child in stmt.body):
            return

        test = stmt.test
        if not isinstance(test, ast.Compare):
            return

        if not any(isinstance(op, (ast.In, ast.NotIn)) for op in test.ops):
            return

        nodes = [test.left, *test.comparators]
        hasTraversalLiteral = any(
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and (".." in node.value or "/" in node.value or "\\" in node.value)
            for node in nodes
        )

        if not hasTraversalLiteral:
            return

        for node in nodes:
            if isinstance(node, ast.Name):
                self.pathValidatedVars.add(node.id)

    # Safely evaluates tiny constant expressions in benchmark guards.
    # This reduces FPs from branches whose condition is statically unreachable.
    def constantValue(self, node: ast.AST) -> object | None:
        if isinstance(node, ast.Constant):
            return node.value

        # Resolves names assigned to simple constants in this function.
        # This lets ternary guards like num > 100 choose the reachable branch.
        if isinstance(node, ast.Name):
            return self.constantValueMap.get(node.id)

        #  Carries constants through statically-known ternary branches.
        # This pairs with evaluateExpressionTaint's IfExp branch selection.
        if isinstance(node, ast.IfExp):
            testValue = self.constantValue(node.test)

            if testValue is True:
                return self.constantValue(node.body)

            if testValue is False:
                return self.constantValue(node.orelse)

            return None

        if isinstance(node, ast.UnaryOp):
            operand = self.constantValue(node.operand)
            if operand is None:
                return None

            unaryOps = {
                ast.USub: operator.neg,
                ast.UAdd: operator.pos,
                ast.Not: operator.not_,
            }

            opFunc = unaryOps.get(type(node.op))
            return opFunc(operand) if opFunc else None

        if isinstance(node, ast.BinOp):
            left = self.constantValue(node.left)
            right = self.constantValue(node.right)
            if left is None or right is None:
                return None

            binOps = {
                ast.Add: operator.add,
                ast.Sub: operator.sub,
                ast.Mult: operator.mul,
                ast.FloorDiv: operator.floordiv,
                ast.Mod: operator.mod,
            }

            opFunc = binOps.get(type(node.op))
            if not opFunc:
                return None

            try:
                return opFunc(left, right)
            except Exception:
                return None

        if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
            left = self.constantValue(node.left)
            right = self.constantValue(node.comparators[0])
            if left is None or right is None:
                return None

            compareOps = {
                ast.Eq: operator.eq,
                ast.NotEq: operator.ne,
                ast.Lt: operator.lt,
                ast.LtE: operator.le,
                ast.Gt: operator.gt,
                ast.GtE: operator.ge,
                ast.In: lambda a, b: a in b,
                ast.NotIn: lambda a, b: a not in b,
            }

            opFunc = compareOps.get(type(node.ops[0]))
            if not opFunc:
                return None

            try:
                return opFunc(left, right)
            except Exception:
                return None

        return None
    

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
    def getMatchedPatternCallName(self, rawCallName: str | None, registry: RuleRegistry) -> tuple[set[str], str | None]:
        if not rawCallName:
            return set(), None

        canonicalCallName = self.canonicalizeCallName(rawCallName)

        if canonicalCallName:
            cwes = registry.getSinkCwes(canonicalCallName)
            if cwes:
                return cwes, canonicalCallName

        if rawCallName != canonicalCallName:
            cwes = registry.getSinkCwes(rawCallName)
            if cwes:
                return cwes, rawCallName

        return set(), canonicalCallName or rawCallName

    #Checks if an expression is source tainted and/or does it depend on any function params. Strips the CWE labels off slowly if they do not exist in the function
    #first item it returns is sourceCwes (a set of active source-based CWEs). The second is paramDeps (a dict mapping a param name to the CWEs it could trigger)
    def evaluateExpressionTaint(self, node: ast.AST, params: list[str], registry: RuleRegistry, stmtContext: ast.stmt) -> tuple[set[str], dict[str, set[str]]]:
        if node is None: #no expression, no taint
            return set(), {}

    
        sourceCwes: set[str] = set() #set of cwes that are definitely tainted, like input()
        paramDeps: dict[str, set[str]] = defaultdict(set) #params that have the potential to become tainted

        # Evaluates statically-known ternary branches precisely
        # This prevents dead branches from leaking taint into safe assignments
        if isinstance(node, ast.IfExp):
            testValue = self.constantValue(node.test)

            if testValue is True:
                return self.evaluateExpressionTaint(node.body, params, registry, stmtContext)

            if testValue is False:
                return self.evaluateExpressionTaint(node.orelse, params, registry, stmtContext)

        #is the node a func/method call
        if isinstance(node, ast.Call):
            callName = self.getCallName(node)

            #Reads taint back out of map/config get calls
            #This covers dict.get(...) and ConfigParser.get(...)
            configGetPath = self.configGetPathFromCall(node)
            if configGetPath:
                storedSrc, storedDeps = self.loadSymbolTaint(configGetPath)
                sourceCwes.update(storedSrc)
                self.mergeParamDeps(paramDeps, storedDeps)
            
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
                canonicalCallName = self.canonicalizeCallName(callName) or callName

                #  Response constructors carry XSS only from body content.
                # Header/cookie taint in make_response((body, headers)) is not reflected HTML.
                if canonicalCallName in {"make_response", "flask.make_response", "Response", "flask.Response"}:
                    routeBodyExpr = self.routeReturnBodyExpr(node)

                    if routeBodyExpr and routeBodyExpr is not node:
                        bodySrc, bodyDeps = self.evaluateExpressionTaint(routeBodyExpr, params, registry, stmtContext)
                        sourceCwes.discard("CWE-79")

                        if "CWE-79" in bodySrc:
                            sourceCwes.add("CWE-79")

                        for pName in list(paramDeps.keys()):
                            paramDeps[pName].discard("CWE-79")
                            if not paramDeps[pName]:
                                del paramDeps[pName]

                        for pName, cwes in bodyDeps.items():
                            if "CWE-79" in cwes:
                                paramDeps[pName].add("CWE-79")

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

        if isinstance(node, ast.Subscript):
            #Treats data['key'] as a first-class taintable expr
            #This recovers dict/list/map flows before the normal recursive fallback
            symbol = self.accessPath(node)

            if symbol:
                storedSrc, storedDeps = self.loadSymbolTaint(symbol)
                sourceCwes.update(storedSrc)
                self.mergeParamDeps(paramDeps, storedDeps)

            childSrc, childDeps = self.evaluateExpressionTaint(node.value, params, registry, stmtContext)
            sourceCwes.update(childSrc)
            self.mergeParamDeps(paramDeps, childDeps)

            return sourceCwes, paramDeps
        
        if isinstance(node, ast.Attribute):

            #Attribute reads now check stored access-path taint too
            #This lets holder.value carry taint from earlier holder.value = source
            fullName = self.recursiveGetter(node)

            if fullName:
                storedSrc, storedDeps = self.loadSymbolTaint(fullName)
                sourceCwes.update(storedSrc)
                self.mergeParamDeps(paramDeps, storedDeps)

                sanitizerToCwes, _ = self.getSanitizerCwesForCall(fullName, registry)

                if sanitizerToCwes:
                    sourceCwes -= sanitizerToCwes

                    for pName in list(paramDeps.keys()):
                        paramDeps[pName] -= sanitizerToCwes
                        if not paramDeps[pName]:
                            del paramDeps[pName]

                newSrcCwes, _ = self.getSourceCwesForCall(fullName, registry)
                sourceCwes.update(newSrcCwes)

            childSrc, childDeps = self.evaluateExpressionTaint(node.value, params, registry, stmtContext)
            sourceCwes.update(childSrc)

            for pName, cwes in childDeps.items():
                paramDeps[pName].update(cwes)

            return sourceCwes, paramDeps

        if isinstance(node, ast.BinOp):

            #Makes path/string composition explicitly taint-preserving
            #This covers base / user_path and query + user_value shapes
            leftSrc, leftDeps = self.evaluateExpressionTaint(node.left, params, registry, stmtContext)
            rightSrc, rightDeps = self.evaluateExpressionTaint(node.right, params, registry, stmtContext)

            sourceCwes.update(leftSrc)
            sourceCwes.update(rightSrc)
            self.mergeParamDeps(paramDeps, leftDeps)
            self.mergeParamDeps(paramDeps, rightDeps)

            return sourceCwes, paramDeps

        #is the node a variable
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):

            #Simple names also consult the access-path map.
            #This keeps returned/replayed and container-derived symbols aligned
            storedSrc, storedDeps = self.loadSymbolTaint(node.id)
            sourceCwes.update(storedSrc)
            self.mergeParamDeps(paramDeps, storedDeps)

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

            #Applies simple path validation facts at read time.
            # The variable can still carry other CWEs; only traversal is removed.
            if node.id in self.pathValidatedVars:
                sourceCwes.discard("CWE-22")

                for pName in list(paramDeps.keys()):
                    paramDeps[pName].discard("CWE-22")
                    if not paramDeps[pName]:
                        del paramDeps[pName]
                        
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
    def checkPatternBased(self,stmt: ast.stmt, registry: RuleRegistry, summary: FunctionSummary) -> None:
        lineno = getattr(stmt, "lineno", "Unknown")

        patternRegistry = RuleRegistry(registry.patternRules)
        patternRulesByCwe = {rule.cwe: rule for rule in registry.patternRules}

       
        def recordPattern(rule: VulnerabilityRule, matchedName: str) -> None:
            sig = ("PATTERN", rule.cwe, matchedName, ast.unparse(stmt).strip(), lineno)
            if sig in summary._reportedLocalSigs:
                return

            summary._reportedLocalSigs.add(sig)
            summary.bannedPatterns.append({
                "vulnerability": f"Static Pattern Match: {rule.name}",
                "cwe": rule.cwe,
                "offendingCode": ast.unparse(stmt).strip(),
                "line": lineno,
                "matchedVariable": matchedName,
            })

        # Matches secret-looking names case-insensitively.
        # Used by assignment, dict, keyword, and subscript pattern cases.
        def matchingPatternRules(name: str) -> list[VulnerabilityRule]:
            lowered = name.lower()
            matches = []

            for rule in registry.patternRules:
                if any(lowered == sink.lower() for sink in rule.sinks):
                    matches.append(rule)

            return matches

        # Matches secret-looking literal prefixes/content.
        # This catches tokens even when the variable name is not exact.
        def literalPatternRules(literal: str) -> list[VulnerabilityRule]:
            matches = []

            for rule in registry.patternRules:
                if rule.cwe != "CWE-798":
                    continue

                for sink in rule.sinks:
                    if sink and sink in literal:
                        matches.append(rule)
                        break

            return matches

        # Looks for sensitive identifiers inside an expression.
        # Used for context-specific SHA-2 password-storage findings.
        def expressionHasSensitiveName(node: ast.AST) -> bool:
            sensitiveParts = {
                "password",
                "passwd",
                "pwd",
                "secret",
                "token",
                "api_key",
                "private_key",
                "session_id",
            }

            for child in ast.walk(node):
                if isinstance(child, ast.Name):
                    lowered = child.id.lower()
                    if any(part in lowered for part in sensitiveParts):
                        return True

                if isinstance(child, ast.Attribute):
                    lowered = child.attr.lower()
                    if any(part in lowered for part in sensitiveParts):
                        return True

            return False

        for node in ast.walk(stmt):
            if not isinstance(node, ast.Call):
                continue

            callName = self.getCallName(node)
            if not callName:
                continue

            matchedCwes, matchedCallName = self.getMatchedPatternCallName(
                callName,
                patternRegistry,
            )

            for cwe in matchedCwes:
                matchedRule = patternRulesByCwe.get(cwe)
                ruleName = matchedRule.name if matchedRule else "Pattern-Based Rule"

                summary.bannedPatterns.append({
                    "vulnerability": f"Static Pattern Match: {ruleName}",
                    "cwe": cwe,
                    "offendingCode": ast.unparse(stmt).strip(),
                        "line": lineno,
                        "matchedCall": matchedCallName,
                })

            # Pattern-matches hashlib.new('md5'/'sha1') by literal argument.
            # The call name alone is generic, so the weak algorithm lives in arg[0].
            canonicalCallName = self.canonicalizeCallName(callName) or callName
            if canonicalCallName == "hashlib.new" and node.args:
                firstArg = node.args[0]

                if isinstance(firstArg, ast.Constant) and isinstance(firstArg.value, str):
                    algorithm = firstArg.value.lower().replace("-", "")

                    if algorithm in {"md5", "sha1"}:
                        for cwe in {"CWE-327", "CWE-328"}:
                            matchedRule = patternRulesByCwe.get(cwe)
                            if not matchedRule:
                                continue

                            summary.bannedPatterns.append({
                                "vulnerability": f"Static Pattern Match: {matchedRule.name}",
                                "cwe": cwe,
                                "offendingCode": ast.unparse(stmt).strip(),
                                "line": lineno,
                                "matchedCall": f"hashlib.new({algorithm})",
                            })

            # Reports SHA-2 only when used directly on sensitive values.
            # This catches password hashing misuse without flagging ordinary SHA-2 usage.
            canonicalCallName = self.canonicalizeCallName(callName) or callName
            if canonicalCallName in {"hashlib.sha256", "hashlib.sha512"} and any(expressionHasSensitiveName(arg) for arg in node.args):
                matchedRule = patternRulesByCwe.get("CWE-327")

                if matchedRule:
                    summary.bannedPatterns.append({
                        "vulnerability": f"Static Pattern Match: {matchedRule.name}",
                        "cwe": "CWE-327",
                        "offendingCode": ast.unparse(stmt).strip(),
                        "line": lineno,
                        "matchedCall": canonicalCallName,
                    })

        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            value = stmt.value

            #Assignment checks no longer return early.
            # That lets dict/keyword/subscript pattern checks run on the same stmt.
            if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value.strip():
                for target in targets:
                    target_names = []

                    if isinstance(target, ast.Name):
                        target_names.append(target.id)

                    elif isinstance(target, ast.Attribute):
                        target_names.append(target.attr)

                    for target_name in target_names:
                        for rule in matchingPatternRules(target_name) + literalPatternRules(value.value):
                            recordPattern(rule, target_name)

        # Detects hardcoded secrets in dict literals.
        # Example: {"api_key": "literal-secret"}.
        for node in ast.walk(stmt):
            if not isinstance(node, ast.Dict):
                continue

            for keyNode, valueNode in zip(node.keys, node.values):
                if not (
                    isinstance(keyNode, ast.Constant)
                    and isinstance(keyNode.value, str)
                    and isinstance(valueNode, ast.Constant)
                    and isinstance(valueNode.value, str)
                    and valueNode.value.strip()
                ):
                    continue

                for rule in matchingPatternRules(keyNode.value) + literalPatternRules(valueNode.value):
                    recordPattern(rule, keyNode.value)

        #Detects hardcoded secrets passed as keyword args.
        # Example: Client(api_key="literal-secret").
        for node in ast.walk(stmt):
            if not isinstance(node, ast.keyword) or not node.arg:
                continue

            if not (isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and node.value.value.strip()):
                continue

            for rule in matchingPatternRules(node.arg) + literalPatternRules(node.value.value):
                recordPattern(rule, node.arg)

        # Detects hardcoded secrets assigned into mapping keys.
        # Example: config["secret_key"] = "literal-secret".
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            value = stmt.value

            if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value.strip():
                for target in targets:
                    if not isinstance(target, ast.Subscript):
                        continue

                    key = self.subscriptKey(target.slice)
                    if not key:
                        continue

                    keyName = key.strip("'\"")
                    for rule in matchingPatternRules(keyName) + literalPatternRules(value.value):
                        recordPattern(rule, keyName)



    #Take one function -> Analyze it locally -> Return a FunctionSummary
    #I wanted to modularize this more, but i am genuinely too scared and too tired to try, so bear with the block of code lol
    def buildSummary(self, funcInfo: FunctionInfo, cfgObj: cfg, registry: RuleRegistry, importAliasMap: dict[str, str]):

        #track the srcs and params for the func being checked ONLY
        self.sourceTaintedMap = {}
        self.paramTaintedMap = defaultdict(lambda: defaultdict(set))

        # Reset access-path taint for this function summary build.
        # These maps track obj.attr, dict['key'], and ConfigParser slots.
        self.symbolSourceTaintMap = {}
        self.symbolParamTaintMap = defaultdict(lambda: defaultdict(set))
        self.importAliasMap = importAliasMap

        #Reset per-function semantic guard state.
        # These are local facts and should never bleed between summaries.
        self.unsafeXmlParserVars = set()
        self.pathValidatedVars = set()
        self.constantValueMap = {}

        fullName = funcInfo.globalName

        summary = FunctionSummary(functionName=fullName)
        isRouteHandler = self.isRouteHandler(funcInfo)

        # Pre-scan semantic guards from the raw function AST.
        # CFG blocks may split structured If/Try nodes before guard detection sees them.
        for rawNode in ast.walk(funcInfo.node):
            if isinstance(rawNode, ast.If):
                self.recordPathValidationFacts(rawNode)

            if isinstance(rawNode, ast.stmt):
                self.recordXmlParserConfig(rawNode)

        
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
                self.recordXmlParserConfig(stmt)
                self.recordPathValidationFacts(stmt)

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
                    if isinstance(stmt, ast.For):
                        # Transfers taint from iterables into loop targets.
                        # This catches request.form.keys() / headers.keys() payload names.
                        iterSrc, iterDeps = self.evaluateExpressionTaint(stmt.iter, params, registry, stmt)
                        targetPaths: list[str] = []

                        def collectTarget(target: ast.AST) -> None:
                            if isinstance(target, (ast.Tuple, ast.List)):
                                for elt in target.elts:
                                    collectTarget(elt)
                                return

                            path = self.accessPath(target)
                            if path:
                                targetPaths.append(path)

                        collectTarget(stmt.target)

                        for targetPath in targetPaths:
                            if self.recordSymbolTaint(targetPath, iterSrc, iterDeps):
                                changed = True

                        if stmt in self.rda.definitionLookup:
                            for varName in self.rda.definitionLookup[stmt]:
                                defi = self.rda.definitionLookup[stmt][varName]

                                if iterSrc:
                                    oldLen = len(self.sourceTaintedMap.setdefault(defi, set()))
                                    self.sourceTaintedMap[defi].update(iterSrc)

                                    if len(self.sourceTaintedMap[defi]) > oldLen:
                                        changed = True

                                for pName, cwes in iterDeps.items():
                                    oldLen = len(self.paramTaintedMap[defi][pName])
                                    self.paramTaintedMap[defi][pName].update(cwes)

                                    if len(self.paramTaintedMap[defi][pName]) > oldLen:
                                        changed = True

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
                        assignedAccessPaths = self.getAssignedAccessPaths(stmt)

                        # Records simple constant assignments for guard evaluation.
                        # Non-constant writes clear the old fact to avoid stale precision.
                        constantRhs = self.constantValue(rhsNode)
                        for assignedPath in assignedAccessPaths:
                            if constantRhs is None:
                                self.constantValueMap.pop(assignedPath, None)
                            else:
                                self.constantValueMap[assignedPath] = constantRhs

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

                        #  Records assignment taint on access paths.
                        # This is the main transfer for dict['k'] and obj.field flows.
                        for assignedPath in assignedAccessPaths:
                            # Safe overwrites now kill previous access-path taint.
                            # This fixes stale taint after bar = tainted; bar = "safe".
                            if not sourceCwes and not paramDeps:
                                if self.clearSymbolTaint(assignedPath):
                                    changed = True
                                continue

                            if self.recordSymbolTaint(assignedPath, sourceCwes, paramDeps):
                                changed = True

                        #Splits dict literals into key-specific access paths.
                        # Example: bag = {'sql': tainted} records bag['sql'] as tainted.
                        if isinstance(rhsNode, ast.Dict):
                            for assignedPath in assignedAccessPaths:
                                for keyNode, valueNode in zip(rhsNode.keys, rhsNode.values):
                                    key = self.subscriptKey(keyNode)

                                    if not key:
                                        continue

                                    valueSrc, valueDeps = self.evaluateExpressionTaint(valueNode, params, registry, stmt)
                                    dictPath = f"{assignedPath}[{key}]"

                                    if self.recordSymbolTaint(dictPath, valueSrc, valueDeps):
                                        changed = True

                    elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                        # Models list/set append-like calls as container taint writes.
                        # A later lst[0], lst.pop(), or ''.join(lst) can recover that taint.
                        callNode = stmt.value
                        if isinstance(callNode.func, ast.Attribute) and callNode.func.attr in {"append", "add"} and callNode.args:
                            receiver = self.accessPath(callNode.func.value)

                            if receiver:
                                valueSrc, valueDeps = self.evaluateExpressionTaint(callNode.args[0], params, registry, stmt)

                                if self.recordSymbolTaint(f"{receiver}[*]", valueSrc, valueDeps):
                                    changed = True

                        # Models ConfigParser-style set(...) as a taint write.
                        # This keeps conf.set(..., tainted) linked to later conf.get(...).
                        configPath, valueNode = self.configSetTargetFromCall(stmt.value)

                        if configPath and valueNode:
                            valueSrc, valueDeps = self.evaluateExpressionTaint(valueNode, params, registry, stmt)

                            if self.recordSymbolTaint(configPath, valueSrc, valueDeps):
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

                    if isRouteHandler:

                        #  Route-return XSS now inspects body taint only.
                        # This avoids counting tainted headers/json/redirects as reflected HTML.
                        routeBodyExpr = self.routeReturnBodyExpr(stmt.value)
                        routeReturnCwes = set()
                        routeParamDeps = {}

                        if routeBodyExpr and self.routeReturnHasXssEvidence(routeBodyExpr, funcInfo):
                            routeSourceCwes, routeParamDeps = self.evaluateExpressionTaint(routeBodyExpr, params, registry, stmt)
                            routeReturnCwes = routeSourceCwes & {"CWE-79"}

                        for cwe in routeReturnCwes:
                            localSig = (fullName, cwe, "route_return", ast.unparse(routeBodyExpr).strip(), getattr(stmt, "lineno", 0))

                            if localSig not in summary._reportedLocalSigs:
                                summary._reportedLocalSigs.add(localSig)
                                summary.localVulnerabilities.append({
                                    "vulnerability": "Route Return XSS Flow",
                                    "cwe": cwe,
                                    "sink": "route_return",
                                    "expression": ast.unparse(routeBodyExpr).strip(),
                                    "line": getattr(stmt, "lineno", "Unknown")
                                })

                        for pName, cwes in routeParamDeps.items():
                            if "CWE-79" not in cwes:
                                continue

                            if pName not in summary.paramsToSinks:
                                summary.paramsToSinks[pName] = defaultdict(list)

                            if "route_return" not in summary.paramsToSinks[pName]["CWE-79"]:
                                summary.paramsToSinks[pName]["CWE-79"].append("route_return")


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
                        sinkCwes = self.refineSinkCwesForCall(node, matchedSinkName, sinkCwes)
                        
                        if matchedSinkName and sinkCwes:
                            if matchedSinkName not in summary.sinkCalls:
                                summary.sinkCalls.append(matchedSinkName)

                            # Sink argument selection is now CWE-aware.
                            # SQLi checks the query arg, while other sinks keep normal behavior.
                            argsToCheck = self.relevantSinkArgs(node, matchedSinkName, sinkCwes)
                            
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

        #scanner carries local source facts into interprocedural propagation
        for defi, cwes in self.sourceTaintedMap.items():
            if cwes:
                summary.localSourceVars[defi.var].update(cwes)

        #Exports access-path local taint into interprocedural scopes.
        #Replay can now see tainted names like holder.value or data['key'].
        for varName, cwes in self.symbolSourceTaintMap.items():
            if cwes:
                summary.localSourceVars[varName].update(cwes)

        #This converts parameter dependency facts into the summary
        for defi, deps in self.paramTaintedMap.items():
            for pName, cwes in deps.items():
                if cwes:
                    summary.paramDependentVars[defi.var][pName].update(cwes)

        #Exports param-dependent access paths into the summary too.
        #This preserves caller-controlled container/object fields across calls
        for varName, deps in self.symbolParamTaintMap.items():
            for pName, cwes in deps.items():
                if cwes:
                    summary.paramDependentVars[varName][pName].update(cwes)

        return summary
