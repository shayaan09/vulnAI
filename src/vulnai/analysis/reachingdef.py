from vulnai.analysis.bb import BasicBlock as bb
from vulnai.analysis.definition import Definition as defi
import ast
from vulnai.analysis.cfg import ControlFlowGraph as cfg
from collections import defaultdict

class ReachingDefinitionAnalyzer:
    def __init__(self):
        self.definitionID = 0
        self.allDefs = defaultdict(set)
        self.definitionLookup= defaultdict(dict) #Mapping: stmt -> varName -> Definition CREATED here


    #Collects ALL var definitions globally
    def defCollect(self, block: bb):
        for stmt in block.statements:
           if isinstance(stmt, ast.Assign):
                
                for target in stmt.targets:
                    if isinstance(target, ast.Name):

                        #Wrapping in a list to save the string iteration problem. if a var is named 'data', the coming for loop will iterate over EAXH CHARACTER in the word.
                        varNames = [target.id]
                    elif isinstance(target, ast.Tuple) or isinstance(target, ast.List):
                        varNames = []
                        for elt in target.elts:
                            if isinstance(elt, ast.Name):
                                varNames.append(elt.id)
                    else:
                        continue

                    for varName in varNames:
                        self.definitionID += 1
                        newDef = defi(self.definitionID, varName, stmt)
                        self.allDefs[varName].add(newDef)
                        block.definitions.append(newDef)
                        self.definitionLookup[stmt][varName] = newDef

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




