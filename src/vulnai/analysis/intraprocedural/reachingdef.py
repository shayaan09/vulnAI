from vulnai.analysis.intraprocedural.bb import BasicBlock as bb
from vulnai.analysis.intraprocedural.definition import Definition as defi
import ast
from vulnai.analysis.intraprocedural.cfg import ControlFlowGraph as cfg
from collections import defaultdict

class ReachingDefinitionAnalyzer:
    def __init__(self):
        self.definitionID = 0
        self.allDefs = defaultdict(set)
        self.definitionLookup= defaultdict(dict) #Mapping: stmt -> varName -> Definition CREATED here


    #Recursively unpacks targets
    def extractNames(self, targetNode) -> list:
        names = []

        if isinstance(targetNode, ast.Name):
            names.append(targetNode.id)

        elif isinstance(targetNode, (ast.Tuple, ast.List)):
            for elt in targetNode.elts:
                names.extend(self.extractNames(elt))

        return names


    #Collects ALL var definitions globally
    def defCollect(self, block: bb):

        collectedVarNames = []

        for stmt in block.statements:
            varNames = []
            
            #Standard Assignment (x = y)
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    varNames.extend(self.extractNames(target))
                    
            #Aug Assignment (x += 1)
            elif isinstance(stmt, ast.AugAssign):
                varNames.extend(self.extractNames(stmt.target))
                
            #Ann Assignment (x: int = 5)
            elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
                varNames.extend(self.extractNames(stmt.target))
                
            #For-Loop Iterators (for x in obj:)
            elif isinstance(stmt, (ast.For, ast.AsyncFor)):
                varNames.extend(self.extractNames(stmt.target))
                
            #Context Managers (with open() as f:)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    if item.optional_vars:
                        varNames.extend(self.extractNames(item.optional_vars))
                        
            #Exception Handlers (except Exception as e:)
            elif isinstance(stmt, ast.ExceptHandler) and stmt.name:
                varNames.append(stmt.name)
                
            #Function Params 
            elif isinstance(stmt, ast.arguments):
                for arg in stmt.args + getattr(stmt, 'kwonlyargs', []) + getattr(stmt, 'posonlyargs', []):
                    varNames.append(arg.arg)

                if stmt.vararg:
                    varNames.append(stmt.vararg.arg)

                if stmt.kwarg:
                    varNames.append(stmt.kwarg.arg)
            
            for varName in varNames:
                self.definitionID += 1
                newDef = defi(self.definitionID, varName, stmt)
                self.allDefs[varName].add(newDef)
                block.definitions.append(newDef)
                self.definitionLookup[stmt][varName] = newDef
            
            collectedVarNames.extend(varNames)
            
        return collectedVarNames

    #Walks through all definitions in a block and updates the GEN and KILL sets
    #Locally: checks for any same definitions within the block and deletes them
    #Globally: updates the local block's KILL set by checking if any prev defs exist with the same var name globally in the allDefs list
    def defHandle(self, block: bb):
        block.GEN = set()
        block.KILL = set()

        for definition in block.definitions:
                varName = definition.var
                oldDefs = set()

                #for any defs of a var created in the working block
                for defin in block.GEN:
                    if defin.var == varName:
                        oldDefs.add(defin)


                block.GEN -= oldDefs
                block.KILL |= oldDefs

                block.KILL |= self.allDefs[varName] - {definition} #block kills every other instance of that variable in the program except the one it just made
                block.GEN.add(definition)

                

    
    #At the beginning I assume nothing reaches any block, so init all IN sets as empty and all OUT sets to just be copies of our GEN sets, since OUT = GEN U [IN - KILL]
    def transferFunction(self, cfg: cfg):
        for block in cfg.blocks:
            block.IN = set()
            block.OUT = block.GEN.copy()

        changed = True

        while changed:
            changed = False

            for block in cfg.blocks:
            
                oldIN = block.IN.copy()
                oldOUT = block.OUT.copy()

                newIN = set()
                for prevBlock in block.prevBlocks:
                    newIN |= prevBlock.OUT

                newOUT = block.GEN | (newIN - block.KILL)

                block.IN = newIN
                block.OUT = newOUT

                #Keep looping until the IN and OUT sets stop changing each iteration
                if block.IN != oldIN or block.OUT != oldOUT:
                    changed = True




