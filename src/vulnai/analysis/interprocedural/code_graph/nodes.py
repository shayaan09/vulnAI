from dataclasses import dataclass, field
from typing import  Any

@dataclass
class GraphNode:
    id: str                 #e.g "module: auth.login" or "function: auth.login.verify"
    nodeType: str               #"MODULE" or "FUNCTION"
    ref: str                #Points to structured storage, aka the dictionary key in CodebaseIndex (moduleName or globalName)
    metadata: dict[str, Any] = field(default_factory=dict) #for random extra details i might need

