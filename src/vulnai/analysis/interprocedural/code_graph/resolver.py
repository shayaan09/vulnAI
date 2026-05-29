from dataclasses import dataclass, field
from typing import Dict, Any, Optional
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


@dataclass
class ResolvedSymbol:

    #globalName is optional bcz if the function is nuilt-in like print(), or completely unkonw, there is no internal project destination path, so it gets set to None.
    globalName: Optional[str]      #e.g "db.run_query" (None if unknown/builtin)
    kind: str                       #From ResolutionKind
    confidence: str                 #"HIGH", "MEDIUM", "LOW"
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class CallSiteInfo:
    
    lineno: int #Line number in the file where the call occurred
    callerFunc: str #global name of the function we are leaving
    calleeFunc: str #global name of the function we are entering
    resolutionKind: str
    confidence: str
    node: ast.Call