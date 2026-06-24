from dataclasses import dataclass, field
from typing import Any
import ast

#Just some str consts
class ResolutionKind:
    localFunction = "LOCAL_FUNCTION"
    fromImport = "FROM_IMPORT"
    moduleAttribute = "MODULE_ATTRIBUTE"
    parameterCall = "PARAMETER_CALL"
    localVariableCall = "LOCAL_VARIABLE_CALL"
    instanceMethod = "INSTANCE_METHOD"
    classMethod = "CLASS_METHOD"
    unresolvedAttribute = "UNRESOLVED_ATTRIBUTE"
    builtin = "BUILTIN"
    externalLibrary = "EXTERNAL_LIBRARY"
    unknown = "UNKNOWN"

#Holds what a function call points to
@dataclass
class ResolvedSymbol:

    kind: str                       #From ResolutionKind
    confidence: str                 #"HIGH", "MEDIUM", "LOW"

    #globalName is optional bcz if the function is built-in like print(), or completely unknown, there is no internal project destination path, so it gets set to None.
    globalName: str | None = None      #e.g "db.run_query" (None if unknown/builtin)
    metadata: dict[str, Any] = field(default_factory=dict)


#Payload attached to a GraphEdge documenting the exact context of a function call
@dataclass
class CallSiteInfo:
    
    lineno: int #Line number in the file where the call occurred
    callerFunc: str #global name of the function we are leaving
    calleeFunc: str #global name of the function we are entering
    resolutionKind: str
    confidence: str
    node: ast.Call
    parentStmt: ast.stmt | None #The full function call. x = execute(), ast.Call would only give us .exectue otherwise