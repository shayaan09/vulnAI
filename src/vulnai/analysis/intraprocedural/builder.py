import ast
from vulnai.analysis.intraprocedural.bb import BasicBlock as bb
from vulnai.analysis.intraprocedural.cfg import ControlFlowGraph as cfg


class Builder:
    def cfgBuild(self, funcNode: ast.FunctionDef) -> cfg:
        newCfg = cfg()

        block = newCfg.blockBuild()
        newCfg.blockConnector(newCfg.entryBlock, block)
        print(f"[BLOCK {newCfg.entryBlock.id}] -> [BLOCK {block.id}]")

        #We grab the args from the function signature and force them 
        #into the very first working block so RDA and UDA can see them
        if funcNode.args.args or getattr(funcNode.args, 'kwonlyargs', []):
            block.statements.append(funcNode.args)

        
        self.recursiveStmtBuild(newCfg, funcNode.body, block)

        return newCfg
    

    #This iterates through different types of ast objects and returns the final block it encounters

    #NOTE: due to the way i designed this, each if statement is a self-contained object (they will create their own join blocks inside of their recursion calls), so, there is an empty join block inside
    #every nested if statement. It has no use and will be ok in design, but can cause confusion in tracing
    def recursiveStmtBuild(self, currentCfg: cfg, statements: list[ast.stmt], block:bb):
        
        for statement in statements:
            if(isinstance(statement, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Expr))):
                block.statements.append(statement)

            elif(isinstance(statement, ast.If)):
                #append the IF statement to the block so UDA can evaluate the condition (e.g if x == 5)
                #NOTE: Because ast.walk will read the whole body if i append the whole node, 
                #i just append the test condition to keep flow-sensitivity accurate
                block.statements.append(statement.test)
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

            elif(isinstance(statement, (ast.For, ast.While))):
                loopHead = currentCfg.blockBuild()
                currentCfg.blockConnector(block, loopHead)
                print(f"[BLOCK {block.id}] -> [BLOCK {loopHead.id}]")

                if isinstance(statement, ast.For):
                    #Wrap in an expression to isolate it from the body for clean AST walking
                    loopHead.statements.append(ast.Expr(value=statement.iter))
                    loopHead.statements.append(ast.Assign(targets=[statement.target], value=ast.Constant(value=None)))
                else:
                    loopHead.statements.append(statement.test)


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






