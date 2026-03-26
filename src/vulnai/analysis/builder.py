import ast
from vulnai.analysis.bb import BasicBlock as bb
from vulnai.analysis.cfg import ControlFlowGraph as cfg

class Builder:
    def cfgBuild(self, funcBody: list[ast.stmt]) -> cfg:
        newCfg = cfg()

        block = newCfg.blockBuild()
        newCfg.blockConnector(newCfg.entryBlock, block)
     

        for statement in funcBody:

            if(isinstance(statement, ast.Assign) or isinstance(statement, ast.Expr)):
                block.statements.append(statement)
            elif(isinstance(statement, ast.If)):



        return newCfg



