import ast
from vulnai.analysis.usedef import UseDefAnalyzer
from vulnai.analysis.reachingdef import ReachingDefinitionAnalyzer
from vulnai.analysis.cfg import ControlFlowGraph as cfg
from vulnai.analysis.vulns import VulnerabilityRule


class TaintAnalyzer:
    def __init__(self, useDefAnalyzer: UseDefAnalyzer, reachingDefAnalyzer: ReachingDefinitionAnalyzer):
        self.uda = useDefAnalyzer
        self.rda = reachingDefAnalyzer
        self.taintedDefs = set()

    #Recursively builds fully constructed call path like:

    #input() -> "input"
    #os.system() -> "os.system"
    #xml.etree.ElementTree.fromstring() -> its different parts
    def recursiveGetter(self, node):
            if isinstance(node, ast.Name):
                return node.id
            
            elif isinstance(node, ast.Attribute):

                prefix = self.recursiveGetter(node.value)

                if prefix:
                    return f"{prefix}.{node.attr}"
                return node.attr
            
            return None
    

    #Helper to extract the string name of a call function or method
    def getCallName(self, callNode: ast.Call):
        return self.recursiveGetter(callNode.func)
    

    def isSource(self, stmt, rule: VulnerabilityRule) -> bool:
        if isinstance(stmt, ast.Assign):

            #Scan the entire RHS tree. If we have x.input().strip(), strip would be considered the outermost call, but we need .input()
            for node in ast.walk(stmt.value):
                if isinstance(node, ast.Call):
                    if self.getCallName(node) in rule.sources:
                        return True
        return False

    def isSink(self, stmt, rule: VulnerabilityRule) -> bool:

        for node in ast.walk(stmt):
            if isinstance(node, ast.Call):
                if self.getCallName(node) in rule.sinks:
                    return True
        return False
    
    #Checks if the RHS of an assignment wraps data in a sanitizing function
    def isSanitizer(self, stmt, rule: VulnerabilityRule) -> bool:
        if isinstance(stmt, ast.Assign):
            for node in ast.walk(stmt.value):
                if isinstance(node, ast.Call):
                    if self.getCallName(node) in rule.sanitizers:
                        return True
        return False

    def flowRun(self, cfg: cfg, rule: VulnerabilityRule) -> bool:

        #Ignore pattern based vulns
        if rule.detectionType != "taintFlow":
            return False
        

        #Marks sources
        allDefins = []
        for block in cfg.blocks:
            for definition in block.definitions:
                allDefins.append(definition)
                if self.isSource(definition.node, rule):
                    self.taintedDefs.add(definition)


        #Propagation step
        changed = True
        while changed:
            changed = False

            for block in cfg.blocks:

                for stmt in block.statements:

                    #If stmt cleanses data, it strips the taint from the definition
                    if self.isSanitizer(stmt, rule):
                        for definition in allDefins:
                            if definition.node == stmt and definition in self.taintedDefs:
                                self.taintedDefs.remove(definition)
                                changed = True
                        continue

                    #Checks if the current stmt uses any variable whose reaching definition is already tainted
                    usesTaint = False
                    for varName in self.uda.useDefEdges[stmt]:
                        for incomingDef in self.uda.useDefEdges[stmt][varName]:
                            if incomingDef in self.taintedDefs:
                                usesTaint = True
                                break
                        if usesTaint:
                            break
                    
                    if usesTaint:
                        for definition in allDefins:
                            if definition.node == stmt and definition not in self.taintedDefs:
                                self.taintedDefs.add(definition)
                                changed = True

        #Sink check
        reportedVulns = False #Assume we found no vulns yet
        for block in cfg.blocks:
            for stmt in block.statements:
                if self.isSink(stmt, rule):

                    uses = self.uda.useCollect(stmt)
                    isVulnerable = False
                    taintedVars = [] #Which vars caused the vulnerability

                    for varName in uses:
                        if stmt in self.uda.useDefEdges and varName in self.uda.useDefEdges[stmt]:
                            incomingDefs = self.uda.useDefEdges[stmt][varName]

                            #Loops through every possible reaching definition
                            for defi in incomingDefs:
                                if defi in self.taintedDefs:
                                    isVulnerable = True
                                    taintedVars.append(varName)

                    if isVulnerable:
                        reportedVulns = True
                        print(f"Tainted data has reached a sink")
                        print(f"Sink Statement: {ast.unparse(stmt).strip()}")
                        print(f"Tainted Variable Reference: {list(set(taintedVars))}\n")
        if not reportedVulns:
            print("No vulnerabilities detected. Execution path is clear.")
        
        return reportedVulns



    def patternRun(self, cfg: cfg, rule: VulnerabilityRule) -> bool:
        
        if rule.detectionType != "patternBased":
            return False

        reportedVulns = False
        for block in cfg.blocks:
            for stmt in block.statements:

                #Walking the AST of the stmt to see if a pattern exists
                for node in ast.walk(stmt):

                    #BANNED CALL PATTERNS
                    if isinstance(node, ast.Call):
                        callName = self.getCallName(node)
                        
                    
                        #If the program uses a banned function, flag it
                        if callName in rule.sinks:
                            reportedVulns = True
                            print(f"[{rule.cwe}] Static Pattern Match: {rule.name}")
                            print(f"Offending Statement: {ast.unparse(stmt).strip()}\n")

                    #BANNED ASSIGNMENT PATTERNS
                    elif isinstance(stmt, ast.Assign):

                        #Check if the target var matches a sink pattern (like API_KEY)
                        isSecretVar = False
                        for target in stmt.targets: #for scanning the RHS of an assignment

                            if isinstance(target, ast.Name) and target.id in rule.sinks:
                                isSecretVar = True
                            elif isinstance(target, ast.Attribute) and target.attr in rule.sinks:
                                isSecretVar = True
                        
                        #If it's a secret var name, check if they are assigning a raw string literal
                        if isSecretVar:

                            #Check if the secret var has been assigned a string constant (an ast.Constant). if yes, high possibility it is a hardcoded value
                            if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                                reportedVulns = True
                                print(f"[{rule.cwe}] Static Pattern Match: {rule.name}")
                                print(f"Offending Assignment: {ast.unparse(stmt).strip()}\n")
                            
        return reportedVulns