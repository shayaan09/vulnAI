from dataclasses import dataclass, field
from vulnai.analysis.interprocedural.structured_storage.function_info import FunctionInfo
from vulnai.analysis.interprocedural.structured_storage.module_info import ModuleInfo
from vulnai.analysis.interprocedural.structured_storage.diagnostic_info import DiagnosticInfo

#Holds info about the entire codebase
@dataclass
class CodebaseIndex:
    rootPath: str
    modules: dict[str, ModuleInfo] = field(default_factory=dict) #key being module name, val being a ModuleInfo obj
    functionTable: dict[str, FunctionInfo] = field(default_factory=dict) #key being func's globalName, val being a FunctionInfo obj

    #maps out the file-to-file dependencies across thh  project
    #key: the file where the import stmts are
    #value: module names that the source file is trying to import
    importGraph: dict[str, set[str]] = field(default_factory=dict)
    diagnostics: list[DiagnosticInfo] = field(default_factory=list)