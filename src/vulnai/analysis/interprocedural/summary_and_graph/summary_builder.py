import ast
from vulnai.analysis.usedef import UseDefAnalyzer
from vulnai.analysis.reachingdef import ReachingDefinitionAnalyzer
from vulnai.analysis.cfg import ControlFlowGraph as cfg
from vulnai.analysis.vulns import VulnerabilityRule
from vulnai.analysis.interprocedural.summary_and_graph.summary_builder import FunctionSummary



class FunctionSummaryBuilder:
    def __init__(self, useDefAnalyzer: UseDefAnalyzer, reachingDefAnalyzer: ReachingDefinitionAnalyzer):
        self.uda = useDefAnalyzer
        self.rda = reachingDefAnalyzer


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
    

    #Take one function -> Analyze it locally -> Return a FunctionSummary
    def buildSummary(self, funcNode: ast.FunctionDef, cfg: cfg, rule: VulnerabilityRule, moduleName: str = "") -> FunctionSummary:

        #creates func's qualified name
        fullName = f"{moduleName}.{funcNode.name}" if moduleName else funcNode.name
        summary = FunctionSummary(functionName=fullName)


        params = [arg.arg for arg in funcNode.args.args]
        
        #Tracking Maps
        localDefsParamTaint = {}  #Definition -> Set of parameter names polluting it. like Def(y) = "x", if x tainted y
        localDefsSrcTainted = set()  #Set of Definitions initialized/tainted by a source. like Def(y) = tainted if y = input()
        

        #Fixed-Point. Repeatedly scans the func until no new taint facts are discovered bcz taint can move thru multiple assignments
        changed = True
        while changed:
            changed = False

            for block in cfg.blocks:
                for stmt in block.statements:

                    #ast.Assign bcz if taint moves from one var to another it usually happens through assignment
                    if isinstance(stmt, ast.Assign):

                        createdDefs = []
                        if stmt in self.rda.definitionLookup:
                            for varName in self.rda.definitionLookup[stmt]:
                                createdDefs.append(self.rda.definitionLookup[stmt][varName])
                            
                        #stmt.value gives the entire subtree of the RHS of a stmt
                        rhsUses = self.uda.useCollect(stmt.value) if hasattr(stmt, 'value') else []
                        
                        #Does this assignment directly call a source or no
                        containsDirectSrc = False
                        for node in ast.walk(stmt.value):
                            if isinstance(node, ast.Call) and self.getCallName(node) in rule.sources:
                                containsDirectSrc = True
                                break
                        

                        usedByParams = set()
                        pollutedBysrc = containsDirectSrc
                        

                        #Checks the RHS of an assignment stmt variable-by-variable to see if any taint flows into the target var
                        for var in rhsUses:
                            
                            #Process Param Paths
                            if var in params:
                                usedByParams.add(var)

                            #Use-Def lookup. Which defs of this var reach this stmt
                            incoming = self.uda.useDefEdges.get(stmt, {}).get(var, set())
                            for incomingDef in incoming:

                                if incomingDef in localDefsParamTaint:
                                    usedByParams.update(localDefsParamTaint[incomingDef])

                                #Process Secondary Source Paths
                                if incomingDef in localDefsSrcTainted:
                                    pollutedBysrc = True
                        
                        for defs in createdDefs:
                            if usedByParams:
                                if defs not in localDefsParamTaint:
                                    localDefsParamTaint[defs] = set()
                                    localDefsParamTaint[defs].update(usedByParams)
                                    changed = True
                                else:
                                    alreadyTracked = localDefsParamTaint[defs]
                                    if not usedByParams.issubset(alreadyTracked):
                                        localDefsParamTaint[defs].update(usedByParams)
                                        changed = True


                            if pollutedBysrc and defs not in localDefsSrcTainted:
                                localDefsSrcTainted.add(defs)
                                changed = True

        for block in cfg.blocks:
            for stmt in block.statements:

                #Handles Returns
                if isinstance(stmt, ast.Return) and stmt.value:

                    for node in ast.walk(stmt.value):
                        if isinstance(node, ast.Call) and self.getCallName(node) in rule.sources:
                            summary.returnsTaint = True
                            summary.directSourceReturn = self.getCallName(node)
                    
                    retUses = self.uda.useCollect(stmt.value)
                    for var in retUses:
                        incoming = self.uda.useDefEdges.get(stmt, {}).get(var, set())
                        for incomingDef in incoming:
                            if incomingDef in localDefsSrcTainted:
                                summary.returnsTainted = True
                        

                        #Check Param Dependency
                        if var in params: 
                            summary.taintedReturnParams.add(var)
                        for incomingDef in incoming:
                            if incomingDef in localDefsParamTaint:
                                summary.taintedReturnParams.update(localDefsParamTaint[incomingDef])


                #Check Sinks
                for node in ast.walk(stmt):

                    if isinstance(node, ast.Call):
                        callName = self.getCallName(node)

                        if callName in rule.sinks:
                            if callName not in summary.sinkCalls: 
                                summary.sinkCalls.append(callName)
                            
                            stmtUses = self.uda.useCollect(stmt)

                            for var in stmtUses:
                                reachedParams = set()

                                if var in params: 
                                    reachedParams.add(var)

                                incoming = self.uda.useDefEdges.get(stmt, {}).get(var, set())
                                for incomingDef in incoming:
                                    if incomingDef in localDefsParamTaint:
                                        reachedParams.update(localDefsParamTaint[incomingDef])
                                
                                for p in reachedParams:
                                    if p not in summary.paramsToSinks: 
                                        summary.paramsToSinks[p] = []
                                    if callName not in summary.paramsToSinks[p]:
                                        summary.paramsToSinks[p].append(callName)
        return summary