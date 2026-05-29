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

    def functionExtractor(self, tree: ast.Module, moduleName: str) -> list[str, FunctionInfo]:
        functions = {}
        

        for node in tree.body:
            if(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
                params = []
        
                for arg in node.args.args:
                    params.append(arg.arg)

                decorators = []
                for dec in node.decorator_list:

                    if isinstance(dec, ast.Name):
                        decorators.append(dec.id)

                    elif isinstance(dec, ast.Attribute):

                        #Handle cases like @classmethod
                        decorators.append(ast.unparse(dec))

                functions[node.name] = FunctionInfo(name = node.name, globalName=f"{moduleName}.{node.name}", moduleName=moduleName, node= node, lineno=node.lineno, endLineno=node.end_lineno, params=params, decorators=decorators, isAsync=isinstance(node, ast.AsyncFunctionDef))
            
        return functions
    
    def build(self, rootPathStr: str) -> CodebaseIndex:
        rootPath = Path(rootPathStr).resolve()
        cbIndex = CodebaseIndex(rootPath=str(rootPath))

        for dirpath, dirnames, filenames in os.walk(rootPath):
            for d in list(dirnames):
                if d in self.junkFolders:
                    dirnames.remove(d)

            for filename in filenames:
                if not filename.endswith('py'):
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





