from pathlib import Path
import ast
from vulnai.analysis.interprocedural.structured_storage.import_info import ImportInfo
from vulnai.analysis.interprocedural.structured_storage.function_info import FunctionInfo
from vulnai.analysis.interprocedural.structured_storage.codebase_index import CodebaseIndex
import os
from vulnai.analysis.interprocedural.structured_storage.module_info import ModuleInfo
from vulnai.analysis.interprocedural.structured_storage.diagnostic_info import DiagnosticInfo


class CodebaseIndexBuilder:
    def __init__(self):
        self.junkFolders = {'__pycache__', '.venv', 'venv', '.git', '.pytest_cache', 'egg-info'}

    def pathToModuleName(self, rootPath: Path, filePath = Path):
        relativePath = filePath.relative_to(rootPath).with_suffix('') #shortcut folder address that starts from a specific location rather than the computer's main root drive
        allStyle = relativePath.as_posix() #uses pathlib. Forces any file path to become Mac/Linux style
        return allStyle.replace("/", ".")
    
    #Pre-seeds ImportInfo so buildImportAliasMap can sort and identify different import styles
    #importExtractor extracts raw import records while the buildImportAliasMap converts those records into local-name -> canonical-name maps
    def importExtractor(self, tree: ast.Module) -> list[ImportInfo]:
        imports = []

        for node in ast.walk(tree):
            if(isinstance(node, ast.Import)):
                for alias in node.names:
                    imports.append(ImportInfo(moduleName=alias.name, importedName=None, alias=alias.asname, kind="import", lineno=node.lineno))
            elif(isinstance(node, ast.ImportFrom)):
                fromModule = node.module or ""

                for alias in node.names:
                    imports.append(ImportInfo(moduleName=fromModule, importedName=alias.name, alias=alias.asname, kind="from_import", lineno=node.lineno))

        return imports
    
    
    def buildImportAliasMap(self, imports: list[ImportInfo]) -> dict[str, str]:
        aliasMap: dict[str, str] = {}

        for imp in imports:

            #Handles:
            #import subprocess
            #import subprocess as sp
            #import xml.etree.ElementTree as ET
            if imp.kind == "import":
                fullModuleName = imp.moduleName

                #import x as y
                if imp.alias:
                    aliasMap[imp.alias] = fullModuleName

                #simple lol. import x
                else:

                    #xml.etree.ElementTree.split(".", 1)[0] = xml
                    topLevelName = fullModuleName.split(".", 1)[0]
                    aliasMap[topLevelName] = topLevelName

            #Handles:
            #from subprocess import Popen
            #from subprocess import Popen as pop
            #from pickle import loads
            #from xml.etree import ElementTree as ET
            elif imp.kind == "from_import":
                fromModule = imp.moduleName
                importedName = imp.importedName

                if not importedName or importedName == '*':
                    continue

                localName = imp.alias or importedName

                #Handles odd case:
                #from . import something
                if fromModule:
                    canonicalName = f"{fromModule}.{importedName}"
                else:
                    canonicalName = importedName

                aliasMap[localName] = canonicalName

        return aliasMap

    #Extracts ALL variations of func inputs like positional, positional-only, keyword-only, *args, and **kwargs
    #like: def run(a, /, b, *, c, *args, **kwargs)
    def paramExtract(self, funcNode: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
        params = []
        argsObj = funcNode.args
        
        #the [] helps with crashing
        for arg in getattr(argsObj, 'posonlyargs', []) + argsObj.args:
            params.append(arg.arg)
        
        for arg in getattr(argsObj, 'kwonlyargs', []):
            params.append(arg.arg)
            
        if argsObj.vararg:
            params.append(argsObj.vararg.arg)
        if argsObj.kwarg:
            params.append(argsObj.kwarg.arg)
            
        return params

    def decoratorExtract(self, funcNode: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
        decorators = []

        for dec in funcNode.decorator_list:
            if isinstance(dec, ast.Name):
                decorators.append(dec.id)

            elif isinstance(dec, ast.Attribute):
                decorators.append(ast.unparse(dec))

            else:
                decorators.append(ast.unparse(dec))

        return decorators

    #Walk through a Python file and register EVERY SINGLE function, including functions nested inside functions and methods inside classes
    def functionExtractor(self, tree: ast.Module, moduleName: str) -> dict[str, FunctionInfo]: #tree is the AST for one python file
        functions: dict[str, FunctionInfo] = {} #key: func's qualified name

        #registers one func and then recursively checks if it contains more functions/classes
        #qualParts: path to the function inside the file
        #parentGlobal: parent’s full name
        def register_func(node: ast.FunctionDef | ast.AsyncFunctionDef, qualParts: list[str], parentGlobal: str | None) -> None:
            local_name = ".".join(qualParts)
            global_name = f"{moduleName}.{local_name}"

            info = FunctionInfo(
                name=node.name,
                globalName=global_name,
                moduleName=moduleName,
                node=node,
                lineno=node.lineno,
                endLineno=getattr(node, "end_lineno", node.lineno),
                params=self.paramExtract(node),
                decorators=self.decoratorExtract(node),
                isAsync=isinstance(node, ast.AsyncFunctionDef),
            )

            #Dynamic metadata; FunctionInfo is not slotted, so this is safe.
            info.localName = local_name
            info.parentGlobalName = parentGlobal

            functions[local_name] = info

            #If the current func contains another function, register that child too
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    register_func(child, qualParts + [child.name], global_name)
                elif isinstance(child, ast.ClassDef): #if the current func contains a class inside it
                    register_class(child, qualParts + [child.name], global_name)

        def register_class(node: ast.ClassDef, qualParts: list[str], parentGlobal: str | None) -> None:
            classGlobal = f"{moduleName}.{'.'.join(qualParts)}"

            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    register_func(child, qualParts + [child.name], classGlobal)
                elif isinstance(child, ast.ClassDef):
                    register_class(child, qualParts + [child.name], classGlobal)

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                register_func(node, [node.name], None)
            elif isinstance(node, ast.ClassDef):
                register_class(node, [node.name], None)

        return functions
            
    
    def build(self, rootPathStr: str) -> CodebaseIndex:
        rootPath = Path(rootPathStr).resolve()
        cbIndex = CodebaseIndex(rootPath=str(rootPath))

        for dirpath, dirnames, filenames in os.walk(rootPath):
            for d in list(dirnames):
                if d in self.junkFolders:
                    dirnames.remove(d)

            for filename in filenames:
                if not filename.endswith('.py'):
                    continue
                    
                filePath = Path(dirpath) / filename #combine the directroy path with the filename to get the file address
                moduleName = self.pathToModuleName(rootPath, filePath)

                modInfo = ModuleInfo(moduleName=moduleName, filePath=str(filePath))

                try:
                    #opens file on the hard drive
                    with open(filePath, 'r', encoding='utf-8') as f:
                        sourceCode = f.read() #reads the entire file as a single giant string and stores it in the var
                    
                    #Converts the stringified code into an AST
                    tree = ast.parse(sourceCode, filename=str(filePath))
                    modInfo.astTree = tree
                    
                    modInfo.imports = self.importExtractor(tree)
                    modInfo.importAliasMap = self.buildImportAliasMap(modInfo.imports)
                    modInfo.functions = self.functionExtractor(tree, moduleName)
                    
                    #Add module info to the global CodeBaseIndex class
                    cbIndex.modules[moduleName] = modInfo
                    
                    #Add all func info to the global CodeBaseIndex class. values() completely ignores the keys in a set
                    for funcData in modInfo.functions.values():
                        cbIndex.functionTable[funcData.globalName] = funcData
                    
                    if moduleName not in cbIndex.importGraph:
                        cbIndex.importGraph[moduleName] = set()


                    for imp in modInfo.imports:
                        cbIndex.importGraph[moduleName].add(imp.moduleName)
                    
                except Exception as exc:
                    modInfo.parseError = f"Failed to parse module '{moduleName}': {str(exc)}"
                    
                    lineno = getattr(exc, 'lineno', 0)

                    if lineno is not None:
                        result = lineno
                    else:
                        result = 0

                    cbIndex.diagnostics.append(DiagnosticInfo(filePath=str(filePath), message=f"Failed to parse module '{moduleName}': {str(exc)}", lineno=result, severity="ERROR"))
                    
                    cbIndex.modules[moduleName] = modInfo

        return cbIndex





