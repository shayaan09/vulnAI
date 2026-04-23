from vulnai.analysis.bb import BasicBlock as bb
from vulnai.analysis.definition import Definition as defi
import ast
from vulnai.analysis.cfg import ControlFlowGraph as cfg
from collections import defaultdict

class ReachingDefinitionAnalyzer:
    def __init__(self):
        self.definitionID = 1
        self.allDefs = defaultdict(set)


    #Collects ALL var definitions globally
    def defCollect(self, block: bb):
        for stmt in block.statements:
            if isinstance(stmt, ast.Assign):

                target = stmt.targets[0]
                if not isinstance(target, ast.Name): #only handles name for now, need to change to handle different assignment types
                    continue  

                varName = target.id

                self.definitionID += 1
                newDef = defi(self.definitionID, varName, stmt)

                self.allDefs[varName].add(newDef)
                block.definitions.append(newDef)

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
    def transferFunction(self, block: bb, cfg: cfg):
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




