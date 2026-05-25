from dataclasses import dataclass, field
from typing import Dict, List, Set
from vulnai.analysis.interprocedural.structured_storage.function_info import FunctionInfo
from vulnai.analysis.interprocedural.structured_storage.module_info import ModuleInfo
from vulnai.analysis.interprocedural.structured_storage.diagnostic_info import DiagnosticInfo

#Holds info about the entire codebase
@dataclass
class CodebaseIndex:
    rootPath: str
    modules: Dict[str, ModuleInfo] = field(default_factory=dict) #key being module name, val being a ModuleInfo obj
    functionTable: Dict[str, FunctionInfo] = field(default_factory=dict)
    importGraph: Dict[str, Set[str]] = field(default_factory=dict)
    diagnostics: List[DiagnosticInfo] = field(default_factory=list)