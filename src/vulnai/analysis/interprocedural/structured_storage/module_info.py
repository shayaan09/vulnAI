import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from vulnai.analysis.interprocedural.structured_storage.import_info import ImportInfo
from vulnai.analysis.interprocedural.structured_storage.function_info import FunctionInfo


#One file's info. Module = official name for a file. db.py's module name is db
@dataclass
class ModuleInfo:
    moduleName: str
    filePath: str
    #None tells Python's runtime constructor these are optional
    astTree: Optional[ast.Module | None] = None #The parsed AST for the entire file
    parseError: Optional[str | None] = None
    
    imports: List[ImportInfo] = field(default_factory=list)
    functions: Dict[str, FunctionInfo] = field(default_factory=dict)
    
    classes: List[str] = field(default_factory=list)
    globals: List[str] = field(default_factory=list) #Stores module-level assignments like API KEY  