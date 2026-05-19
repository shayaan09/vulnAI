from vulnai.analysis.cfg import ControlFlowGraph as cfg
import ast 
from vulnai.analysis.reachingdef import ReachingDefinitionAnalyzer
from collections import defaultdict


#Key Notes:
#the useDefEdges hashmap is different from the one in ReachingDefAnalyzer in a way that useDefEdges answers: "At this statement, this variable is being USED. Which older definitions could its value come from?"
#So, it is looking BACK at already created defs for a var. ReachingDefanalyzer is where these definitions are BORN and stored in definitionLookup.

class UseDefAnalyzer:
    def __init__(self):
        self.useDefEdges = defaultdict(lambda: defaultdict(set))#Map: stmt -> varName -> Definitions (a set) USED here


    #Collects all uses from a stmt, from each statement
    def useCollect(self, stmt):
        uses = []

        for node in ast.walk(stmt):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                uses.append(node.id)
        return uses
    
    def definitionCollect(self, stmt):
        definitions = []

        if(isinstance(stmt, ast.Assign)):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    definitions.append(target.id)

                elif isinstance(target, ast.Tuple) or isinstance(target, ast.List):
                    for elt in target.elts:
                        if isinstance(elt, ast.Name):
                            definitions.append(elt.id)
        return definitions
    
    def analyze(self, cfg: cfg, reachingDefObj: ReachingDefinitionAnalyzer):
        for block in cfg.blocks:
            currentDefs = block.IN.copy()

            for stmt in block.statements:
                defsToDel = set()
                uses = self.useCollect(stmt)

                for varName in uses:
                    for definition in currentDefs:
                        if definition.var == varName:
                            self.useDefEdges[stmt][varName].add(definition) #stmt is where the use occurred


                newDefinition = self.definitionCollect(stmt)
                if not newDefinition:
                    continue

                for varDef in newDefinition:    
                    for definition in currentDefs:
                        if definition.var == varDef:
                            defsToDel.add(definition)

                for definition in defsToDel:
                    currentDefs.remove(definition)


                if stmt in reachingDefObj.definitionLookup:
                    for varName in reachingDefObj.definitionLookup[stmt]:
                        generatedDef = reachingDefObj.definitionLookup[stmt][varName]
                        currentDefs.add(generatedDef)
