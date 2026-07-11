from vulnai.analysis.interprocedural.structured_storage.codebase_index import CodebaseIndex
from vulnai.analysis.interprocedural.code_graph.resolver import ResolutionKind, ResolvedSymbol
import ast


#Enforces Python's LEGB Rule and asks, In this module and this function, what does run_query ( a func ) refer to?
class SymbolResolver:
    def __init__(self, index: CodebaseIndex):
        self.index = index
        self.builtins = {"print", "len", "str", "int", "dict", "list", "set", "range",
            "open", "getattr", "setattr", "isinstance", "enumerate", "zip",
            "min", "max", "sum", "any", "all", "sorted"}
        

    #Recursively builds fully constructed call path like:
    #input() -> "input"
    #os.system() -> "os.system"
    #xml.etree.ElementTree.fromstring() -> its different parts
    def recursiveGetter(self, node) -> str | None:
            if isinstance(node, ast.Name):
                return node.id
            
            elif isinstance(node, ast.Call):
                return self.recursiveGetter(node.func)
            
            elif isinstance(node, ast.Attribute):

                prefix = self.recursiveGetter(node.value)

                if prefix:
                    return f"{prefix}.{node.attr}"
                return node.attr
            
            return None

    def localCandidates(self, currentFunction: str, calledName: str) -> list[str]:
        parts = currentFunction.split(".") if currentFunction else []
        candidates = []

        for i in range(len(parts), -1, -1):
            prefix = parts[:i]
            if prefix:
                candidates.append(".".join(prefix + [calledName]))
            else:
                candidates.append(calledName)

        return candidates
    
    #This handles dotted call names with import aliases like import subprocess as sp to sp.run() -> subprocess.run()
    #answers: Does this call point to a known project function? it is used to resolve project function calls for the call graph
    def canonicalizeDottedName(self, rawName: str, importAliasMap: dict[str, str]) -> str:
        parts = rawName.split(".")
        if not parts:
            return rawName

        first = parts[0]
        if first not in importAliasMap:
            return rawName

        replacement = importAliasMap[first]
        return ".".join([replacement] + parts[1:])
    


    def resolveCall(self, node: ast.Call, currentModule: str, currentFunction: str) -> ResolvedSymbol:
        modInfo = self.index.modules.get(currentModule)
        if not modInfo:
            return ResolvedSymbol(globalName=None, kind=ResolutionKind.unknown, confidence="LOW")

        funcData = modInfo.functions.get(currentFunction)

        #Handles variable shadowing. 
        if funcData and isinstance(node.func, ast.Name):
            calledName = node.func.id

            if calledName in funcData.params:
                return ResolvedSymbol(globalName=None, kind=ResolutionKind.parameterCall, confidence="HIGH", metadata={"name": calledName, "reason": "Target is a function parameter wrapper"})

        
        importAliasMap = getattr(modInfo, "importAliasMap", {}) or {}
      
        
        # for imp in modInfo.imports:
        #     if imp.kind == "from_import":
        #         localName = imp.alias if imp.alias else imp.importedName

        #         if imp.moduleName and imp.importedName:
        #             fromImportMap[localName] = (imp.moduleName, imp.importedName)
            
        #     elif imp.kind == "import":
        #         localName = imp.alias if imp.alias else imp.moduleName
        #         moduleImportSet.add(localName)

        #Plain Name Calls
        if isinstance(node.func, ast.Name):
            calledName = node.func.id

            #Built-in check
            if calledName in self.builtins:
                return ResolvedSymbol(globalName=None, kind=ResolutionKind.builtin, confidence="HIGH", metadata={"name": calledName})

            # Parameter shadowing:
            #
            #   def wrapper(callback):
            #       callback()
            #
            # callback is a parameter, not a known internal function.
            if funcData and calledName in funcData.params:
                return ResolvedSymbol(
                    globalName=None,
                    kind=ResolutionKind.parameterCall,
                    confidence="HIGH",
                    metadata={
                        "name": calledName,
                        "reason": "Target is a function parameter",
                    },
                )
            
            # Lexical/nested local resolution.
            # If currentFunction is "init" and calledName is "post",
            # try "init.post", then "post".
            for candidate in self.localCandidates(currentFunction, calledName):
                if candidate in modInfo.functions:
                    return ResolvedSymbol(
                        globalName=f"{currentModule}.{candidate}",
                        kind=ResolutionKind.localFunction,
                        confidence="HIGH",
                    )

            if calledName in importAliasMap:
                targetGlobal = importAliasMap[calledName]


                if targetGlobal in self.index.functionTable:
                    return ResolvedSymbol(globalName=targetGlobal, kind=ResolutionKind.fromImport, confidence="HIGH")
                


                return ResolvedSymbol(globalName=targetGlobal, kind=ResolutionKind.externalLibrary, confidence="MEDIUM")

        rawDotted = self.recursiveGetter(node.func)
        if rawDotted:
            canonical = self.canonicalizeDottedName(rawDotted, importAliasMap)

            if canonical in self.index.functionTable:
                return ResolvedSymbol(globalName=canonical, kind=ResolutionKind.moduleAttribute, confidence="HIGH")

            return ResolvedSymbol(globalName=canonical, kind=ResolutionKind.unresolvedAttribute, confidence="MEDIUM", metadata={"raw": rawDotted})

        return ResolvedSymbol(globalName=None, kind=ResolutionKind.unknown, confidence="LOW")