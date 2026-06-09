import ast
from dataclasses import dataclass, field
from vulnai.analysis.interprocedural.structured_storage.import_info import ImportInfo
from vulnai.analysis.interprocedural.structured_storage.function_info import FunctionInfo


#One file's info. Module = official name for a file. db.py's module name is db
@dataclass
class ModuleInfo:
    moduleName: str
    filePath: str

    # =None tells Python's runtime constructor these are optional
    astTree: ast.Module | None = None #The parsed AST for the entire file
    parseError: str | None = None
    
    imports: list[ImportInfo] = field(default_factory=list)
    functions: dict[str, FunctionInfo] = field(default_factory=dict)
    
    classes: list[str] = field(default_factory=list)
    globals: list[str] = field(default_factory=list) #Stores module-level assignments like API KEY  