import ast
from vulnai.analysis.bb import BasicBlock as bb
from vulnai.analysis.cfg import ControlFlowGraph as cfg


class Builder:
    def cfgBuild(self, funcBody: list[ast.stmt]) -> cfg:
        newCfg = cfg()

        block = newCfg.blockBuild()
        newCfg.blockConnector(newCfg.entryBlock, block)
        print(f"[BLOCK {newCfg.entryBlock.id}] -> [BLOCK {block.id}]")

        self.recursiveStmtBuild(newCfg, funcBody, block)

        return newCfg
    

    #This iterates through different types of ast objects and returns the final block it encounters

    #NOTE: due to the way i designed this, each if statement is a self-contained object (they will create their own join blocks inside of their recursion calls), so, there is an empty join block inside
    #every nested if statement. It has no use and will be ok in design, but can cause confusion in tracing
    def recursiveStmtBuild(self, currentCfg: cfg, statements: list[ast.stmt], block:bb):
        
        for statement in statements:
            if(isinstance(statement, ast.Assign) or isinstance(statement, ast.Expr)):
                block.statements.append(statement)

            elif(isinstance(statement, ast.If)):
                ifTrue = currentCfg.blockBuild()
                currentCfg.blockConnector(block, ifTrue)
                print(f"[BLOCK {block.id}] -> [BLOCK {ifTrue.id}]")
                trueEnd = self.recursiveStmtBuild(currentCfg, statement.body, ifTrue)


                
                ifFalse = currentCfg.blockBuild()
                currentCfg.blockConnector(block, ifFalse)
               
                print(f"[BLOCK {block.id}] -> [BLOCK {ifFalse.id}]")
                falseEnd = self.recursiveStmtBuild(currentCfg, statement.orelse, ifFalse)

                
                joinBlock = currentCfg.blockBuild()
                currentCfg.blockConnector(trueEnd, joinBlock)
                print(f"[BLOCK {trueEnd.id}] -> [BLOCK {joinBlock.id}]")
                currentCfg.blockConnector(falseEnd, joinBlock)
                print(f"[BLOCK {falseEnd.id}] -> [BLOCK {joinBlock.id}]")
                block = joinBlock

            elif(isinstance(statement, ast.For) or isinstance(statement, ast.While)):
                loopHead = currentCfg.blockBuild()
                currentCfg.blockConnector(block, loopHead)
                print(f"[BLOCK {block.id}] -> [BLOCK {loopHead.id}]")


                loopBody = currentCfg.blockBuild()
                currentCfg.blockConnector(loopHead, loopBody)
                print(f"[BLOCK {loopHead.id}] -> [BLOCK {loopBody.id}]")

                finalBodyBlock = self.recursiveStmtBuild(currentCfg, statement.body, loopBody)
                currentCfg.blockConnector(finalBodyBlock, loopHead)
                print(f"[BLOCK {finalBodyBlock.id}] -> [BLOCK {loopHead.id}]")


                joinBlock = currentCfg.blockBuild()
                currentCfg.blockConnector(loopHead, joinBlock)
                print(f"[BLOCK {loopHead.id}] -> [BLOCK {joinBlock.id}]")

                block = joinBlock
                
            elif(isinstance(statement, ast.Return)):
                block.statements.append(statement)
                currentCfg.blockConnector(block, currentCfg.exitBlock)
                break
            
        
        return block






