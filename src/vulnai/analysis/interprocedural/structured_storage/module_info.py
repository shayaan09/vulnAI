import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from vulnai.analysis.interprocedural.structured_storage.import_info import ImportInfo
from vulnai.analysis.interprocedural.structured_storage.function_info import FunctionInfo


#One file's info
@dataclass
class ModuleInfo:
    moduleName: str
    filePath: str
    astTree: Optional[ast.Module | None] #The parsed AST for the entire file
    parseError: Optional[str | None]
    
    imports: List[ImportInfo] = field(default_factory=list)
    functions: Dict[str, FunctionInfo] = field(default_factory=dict)
    
    classes: List[str] = field(default_factory=list)
    globals: List[str] = field(default_factory=list) #Stores module-level assignments like API KEY  