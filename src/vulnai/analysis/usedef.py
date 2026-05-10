from vulnai.analysis.cfg import ControlFlowGraph as cfg
import ast 
from vulnai.analysis.reachingdef import ReachingDefinitionAnalyzer
from collections import defaultdict

class UseDefAnalyzer:
    def __init__(self):
        self.useDefEdges = defaultdict(set)


    #Collects all uses from a stmt, from each statement
    def useCollect(self, stmt):
        uses = []

        if isinstance(stmt, ast.Assign):
            for node in ast.walk(stmt.value):
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    uses.append(node.id)
        return uses
    
    def definitionCollect(self, stmt):
        definition = []

        if(isinstance(stmt, ast.Assign)):
            if(isinstance(stmt.targets[0], ast.Name)):
                definition.append(stmt.targets[0].id)
        return definition
    
    def analyze(self, cfg: cfg, reachingDefObj: ReachingDefinitionAnalyzer):
        for block in cfg.blocks:
            currentDefs = block.IN.copy()

            for stmt in block.statements:
                defsToDel = set()
                uses = self.useCollect(stmt)

                for varName in uses:
                    for definition in currentDefs:
                        if definition.var == varName:
                            self.useDefEdges[stmt].add(definition) #stmt is where the use occurred


                newDefinition = self.definitionCollect(stmt)
                if not newDefinition:
                    continue

                for definition in currentDefs:
                    if definition.var == newDefinition[0]:
                        defsToDel.add(definition)

                for definition in defsToDel:
                    currentDefs.remove(definition)


                if stmt in reachingDefObj.definitionLookup:
                    currentDefs.add(reachingDefObj.definitionLookup[stmt])

                    


