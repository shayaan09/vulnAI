import ast
from vulnai.analysis.intraprocedural.bb import BasicBlock as bb
from vulnai.analysis.intraprocedural.cfg import ControlFlowGraph as cfg


class Builder:
    def cfgBuild(self, funcNode: ast.FunctionDef) -> cfg:
        newCfg = cfg()

        block = newCfg.blockBuild()
        newCfg.blockConnector(newCfg.entryBlock, block)
        #print(f"[BLOCK {newCfg.entryBlock.id}] -> [BLOCK {block.id}]")

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
                # #print(f"[BLOCK {block.id}] -> [BLOCK {ifTrue.id}]")
                trueEnd = self.recursiveStmtBuild(currentCfg, statement.body, ifTrue)

                ifFalse = currentCfg.blockBuild()
                currentCfg.blockConnector(block, ifFalse)
               
                 ##print(f"[BLOCK {block.id}] -> [BLOCK {ifFalse.id}]")
                falseEnd = self.recursiveStmtBuild(currentCfg, statement.orelse, ifFalse)

                
                joinBlock = currentCfg.blockBuild()
                currentCfg.blockConnector(trueEnd, joinBlock)
                #print(f"[BLOCK {trueEnd.id}] -> [BLOCK {joinBlock.id}]")
                currentCfg.blockConnector(falseEnd, joinBlock)
                #print(f"[BLOCK {falseEnd.id}] -> [BLOCK {joinBlock.id}]")
                block = joinBlock

            elif(isinstance(statement, (ast.For, ast.While))):
                loopHead = currentCfg.blockBuild()
                currentCfg.blockConnector(block, loopHead)
                #print(f"[BLOCK {block.id}] -> [BLOCK {loopHead.id}]")

                if isinstance(statement, ast.For):
                    #Wrap in an expression to isolate it from the body for clean AST walking
                    loopHead.statements.append(ast.Expr(value=statement.iter))
                    loopHead.statements.append(ast.Assign(targets=[statement.target], value=ast.Constant(value=None)))
                else:
                    loopHead.statements.append(statement.test)


                loopBody = currentCfg.blockBuild()
                currentCfg.blockConnector(loopHead, loopBody)
                #print(f"[BLOCK {loopHead.id}] -> [BLOCK {loopBody.id}]")

                finalBodyBlock = self.recursiveStmtBuild(currentCfg, statement.body, loopBody)
                currentCfg.blockConnector(finalBodyBlock, loopHead)
                #print(f"[BLOCK {finalBodyBlock.id}] -> [BLOCK {loopHead.id}]")


                joinBlock = currentCfg.blockBuild()
                currentCfg.blockConnector(loopHead, joinBlock)
                #print(f"[BLOCK {loopHead.id}] -> [BLOCK {joinBlock.id}]")

                block = joinBlock
                
            elif(isinstance(statement, ast.Return)):
                block.statements.append(statement)
                currentCfg.blockConnector(block, currentCfg.exitBlock)
                break

            elif isinstance(statement, ast.Try):
                tryBlock = currentCfg.blockBuild()
                currentCfg.blockConnector(block, tryBlock)

                tryEnd = self.recursiveStmtBuild(currentCfg, statement.body, tryBlock)

                branchEnds = []

                if statement.orelse:
                    elseBlock = currentCfg.blockBuild()
                    currentCfg.blockConnector(tryEnd, elseBlock)
                    elseEnd = self.recursiveStmtBuild(currentCfg, statement.orelse, elseBlock)
                    branchEnds.append(elseEnd)
                else:
                    branchEnds.append(tryEnd)

                for handler in statement.handlers:
                    handlerBlock = currentCfg.blockBuild()
                    currentCfg.blockConnector(tryBlock, handlerBlock)

                    handlerEnd = self.recursiveStmtBuild(
                        currentCfg,
                        handler.body,
                        handlerBlock,
                    )
                    branchEnds.append(handlerEnd)

                joinBlock = currentCfg.blockBuild()

                for branchEnd in branchEnds:
                    currentCfg.blockConnector(branchEnd, joinBlock)

                if statement.finalbody:
                    block = self.recursiveStmtBuild(currentCfg, statement.finalbody, joinBlock)
                else:
                    block = joinBlock

            elif isinstance(statement, ast.Match):
                # NOTE: NEW - Adds Python match/case branches to the CFG.
                # This keeps tainted assignments inside case bodies visible to RDA/UDA.
                block.statements.append(statement.subject)
                branchEnds = []

                for case in statement.cases:
                    caseBlock = currentCfg.blockBuild()
                    currentCfg.blockConnector(block, caseBlock)

                    if case.guard:
                        caseBlock.statements.append(case.guard)

                    caseEnd = self.recursiveStmtBuild(currentCfg, case.body, caseBlock)
                    branchEnds.append(caseEnd)

                joinBlock = currentCfg.blockBuild()

                if not branchEnds:
                    currentCfg.blockConnector(block, joinBlock)

                for branchEnd in branchEnds:
                    currentCfg.blockConnector(branchEnd, joinBlock)

                block = joinBlock

            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                # NOTE: NEW - Adds with/async with bodies without duplicating nested body AST.
                # A shallow with node preserves context-manager defs like "as f".
                withBlock = currentCfg.blockBuild()
                currentCfg.blockConnector(block, withBlock)

                if isinstance(statement, ast.AsyncWith):
                    shallowWith = ast.AsyncWith(
                        items=statement.items,
                        body=[],
                        type_comment=getattr(statement, "type_comment", None),
                    )
                else:
                    shallowWith = ast.With(
                        items=statement.items,
                        body=[],
                        type_comment=getattr(statement, "type_comment", None),
                    )

                ast.copy_location(shallowWith, statement)
                withBlock.statements.append(shallowWith)

                bodyBlock = currentCfg.blockBuild()
                currentCfg.blockConnector(withBlock, bodyBlock)
                bodyEnd = self.recursiveStmtBuild(currentCfg, statement.body, bodyBlock)

                joinBlock = currentCfg.blockBuild()
                currentCfg.blockConnector(bodyEnd, joinBlock)
                block = joinBlock
            
        
        return block






