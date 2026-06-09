import ast
from dataclasses import dataclass


#ID card for one function
#Stores everything vulnAI needs to analyze, resolve, and report on that function.
@dataclass
class FunctionInfo:
    name: str       #Func name (like runQuery())
    globalName: str      #Global name. like db.runQuery()
    moduleName: str         #Which module/file owns it.
    node: ast.FunctionDef | ast.AsyncFunctionDef #The actual AST node
    lineno: int
    endLineno: int
    params: list[str]
    decorators: list[str]
    isAsync: bool