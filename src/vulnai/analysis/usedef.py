from vulnai.analysis.bb import BasicBlock as bb
from vulnai.analysis.cfg import ControlFlowGraph as cfg
import ast 
from vulnai.analysis.reachingdef import ReachingDefinitionAnalyzer
from vulnai.analysis.definition import Definition

class UseDefAnalyzer:
    #Collects all uses from a stmt, from each statement
    def useCollect(self, stmt):
        use = []

        if(isinstance(stmt, ast.Assign)):
            if(isinstance(stmt.value, ast.Name)):
                use.append(stmt.value.id)
        return use
    
    def definitionCollect(self, stmt):
        definition = []

        if(isinstance(stmt, ast.Assign)):
            definition.append(stmt.targets[0].id)
        return definition
    
    def analyze(self, cfg: cfg, reachingDefObj: ReachingDefinitionAnalyzer):
        for block in cfg.blocks:
            currentDefs = block.IN.copy()

            for stmt in block.statements:
                defsToDel = set()

                newDefinition = self.definitionCollect(stmt)
                if not newDefinition:
                    continue

                for definition in currentDefs:
                    if definition.var == newDefinition[0]:
                        defsToDel.add(definition)

                

                for definition in defsToDel:
                    currentDefs.remove(definition)

                currentDefs.add(reachingDefObj.definitionLookup[stmt])

                    


