import ast
from vulnai.analysis.usedef import UseDefAnalyzer
from vulnai.analysis.reachingdef import ReachingDefinitionAnalyzer
from vulnai.analysis.cfg import ControlFlowGraph as cfg
class TaintAnalyzer:
    def __init__(self, useDefAnalyzer: UseDefAnalyzer, reachingDefAnalyzer: ReachingDefinitionAnalyzer):
        self.uda = useDefAnalyzer
        self.rda = reachingDefAnalyzer
        self.taintedDefs = set()

    #Helper to extract the string name of a call function or method
    def getCallName(self, callNode: ast.Call):
            
            #Direct name calls like input()
            if isinstance(callNode.func, ast.Name):
                return callNode.func.id
            
            #Attribute calls like os.system()
            elif isinstance(callNode.func, ast.Attribute):
                return callNode.func.attr
            return None
    
    def isSource(self, stmt) -> bool:
        if isinstance(stmt, ast.Assign):

            #Scan the entire RHS tree. If we have x.input().strip(), strip would be considered the outermost call, but we need .input()
            for node in ast.walk(stmt.value):
                if isinstance(node, ast.Call):
                    callName = self.getCallName(node)
                    if callName in ['input', 'get_secure_data']:
                        return True
        return False

    def isSink(self, stmt) -> bool:

        for node in ast.walk(stmt):
            if isinstance(node, ast.Call):
                callName = self.getCallName(node)
                if callName in ['eval', 'exec', 'system', 'execute']:
                    return True
        return False

    def run(self, cfg: cfg):

        #Marks sources
        allDefins = []
        for block in cfg.blocks:
            for definition in block.definitions:
                allDefins.append(definition)
                if self.isSource(definition.node):
                    self.taintedDefs.add(definition)


        #Propagation step
        changed = True
        while changed:
            changed = False

            for block in cfg.blocks:

                for stmt in block.statements:
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
                if self.isSink(stmt):

                    uses = self.uda.useCollect(stmt)
                    isVulnerable = False
                    taintedVars = [] #Which vars caused the vulnerability

                    for varName in uses:
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