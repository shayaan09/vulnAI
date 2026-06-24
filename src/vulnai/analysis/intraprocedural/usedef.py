from vulnai.analysis.intraprocedural.cfg import ControlFlowGraph as cfg
import ast 
from vulnai.analysis.intraprocedural.reachingdef import ReachingDefinitionAnalyzer
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
    

    #Recursively unpacks targets
    def extractNames(self, target_node) -> list:
        names = []

        if isinstance(target_node, ast.Name):
            names.append(target_node.id)

        elif isinstance(target_node, (ast.Tuple, ast.List)):
            for elt in target_node.elts:
                names.extend(self.extractNames(elt))

        return names
    
    
    def definitionCollect(self, stmt):
        definitions = []
        
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                definitions.extend(self.extractNames(target))

        elif isinstance(stmt, ast.AugAssign):
            definitions.extend(self.extractNames(stmt.target))

        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            definitions.extend(self.extractNames(stmt.target))

        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            definitions.extend(self.extractNames(stmt.target))

        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:

                if item.optional_vars:
                    definitions.extend(self.extractNames(item.optional_vars))

        elif isinstance(stmt, ast.ExceptHandler) and stmt.name:
            definitions.append(stmt.name)

        elif isinstance(stmt, ast.arguments):

            for arg in stmt.args + getattr(stmt, 'kwonlyargs', []) + getattr(stmt, 'posonlyargs', []):
                definitions.append(arg.arg)
                
            if stmt.vararg: definitions.append(stmt.vararg.arg)
            if stmt.kwarg: definitions.append(stmt.kwarg.arg)

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
