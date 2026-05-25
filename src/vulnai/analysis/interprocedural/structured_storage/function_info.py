import ast
from dataclasses import dataclass
from typing import List,Union


#ID card for one function
#Stores everything vulnAI needs to analyze, resolve, and report on that function.
@dataclass
class FunctionInfo:
    name: str       #Func name (like runQuery())
    globalName: str      #Global name. like db.runQuery()
    moduleName: str         #Which module/file owns it.
    node: Union[ast.FunctionDef, ast.AsyncFunctionDef]  #The actual AST node
    lineno: int
    endLineno: int
    params: List[str]
    decorators: List[str]
    isAsync: bool