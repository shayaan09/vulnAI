from vulnai.analysis.interprocedural.structured_storage.codebase_index import CodebaseIndex
from vulnai.analysis.interprocedural.code_graph.resolver import ResolutionKind, ResolvedSymbol
import ast


#Enforces Python's LEGB Rule and asks, In this module and this function, what does run_query ( a func ) refer to?
class SymbolResolver:
    def __init__(self, index: CodebaseIndex):
        self.index = index
        self.builtins = {"print", "len", "str", "int", "dict", "list", "set", "range", "open", "getattr", "setattr"}

    def resolveCall(self, node: ast.Call, currentModule: str, currentFunction: str) -> ResolvedSymbol:
        modInfo = self.index.modules.get(currentModule)
        if not modInfo:
            return ResolvedSymbol(globalName=None, 
            kind=ResolutionKind.unknown,
            confidence="LOW"
            )

        funcData = modInfo.functions.get(currentFunction)

        #Handles variable shadowing. 
        if funcData and isinstance(node.func, ast.Name):
            calledName = node.func.id

            if calledName in funcData.params:
                return ResolvedSymbol(globalName=None, 
                kind=ResolutionKind.parameterCall,
                confidence="HIGH",
                metadata={"name": calledName, "reason": "Target is a function parameter wrapper"}
                )

        
        #Parse local file import structures for resolving references
        #Reconstructs a local lookup table explaining how names are bound inside this specific file
        fromImportMap = {}
        moduleImportSet = set()
        
        for imp in modInfo.imports:
            if imp.kind == "from_import":
                localName = imp.alias if imp.alias else imp.importedName

                if imp.moduleName and imp.importedName:
                    fromImportMap[localName] = (imp.moduleName, imp.importedName)
            
            elif imp.kind == "import":
                localName = imp.alias if imp.alias else imp.moduleName
                moduleImportSet.add(localName)

        #Plain Name Calls
        if isinstance(node.func, ast.Name):
            calledName = node.func.id

            #Built-in check
            if calledName in self.builtins:
                return ResolvedSymbol(
                    globalName=None, 
                    kind=ResolutionKind.builtin, 
                    confidence="HIGH",
                    metadata={"name": calledName}
                )

            #Local function resolution
            if calledName in modInfo.functions:
                return ResolvedSymbol(
                    globalName=f"{currentModule}.{calledName}", 
                    kind=ResolutionKind.localFunction, 
                    confidence="HIGH"
                )

            #'from x import y' check
            if calledName in fromImportMap:
                srcMod, realName = fromImportMap[calledName]
                targetGlobal = f"{srcMod}.{realName}"
                
                #STRICT CHECK: Does this actually point to a known project function?
                if targetGlobal in self.index.functionTable:
                    return ResolvedSymbol(globalName=targetGlobal, kind=ResolutionKind.fromImport, confidence="HIGH")
                else:
                    #Could be an external library function, or a local class instantiation, global var, etc
                    return ResolvedSymbol(globalName=targetGlobal, kind=ResolutionKind.externalLibrary, confidence="MEDIUM")

        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                prefix = node.func.value.id #The part before the dot
                methodName = node.func.attr #The part after

                #'import x' prefix check
                if prefix in moduleImportSet:
                    originalModName = next(
                        (imp.moduleName for imp in modInfo.imports if (imp.alias or imp.moduleName) == prefix), 
                        prefix
                    )
                    targetGlobal = f"{originalModName}.{methodName}"
                    
                    #STRICT CHECK: Verify the attribute is a registered global function
                    if targetGlobal in self.index.functionTable:
                        return ResolvedSymbol(globalName=targetGlobal, kind=ResolutionKind.moduleAttribute, confidence="HIGH")
                    else:
                        return ResolvedSymbol(globalName=targetGlobal, kind=ResolutionKind.unresolvedAttribute, confidence="MEDIUM")
                
                #If the prefix isnt an imported module, its an object instance or class reference
                #e.g self.logger.info() or user_object.save()
                return ResolvedSymbol(
                    globalName=None, 
                    kind=ResolutionKind.unresolvedAttribute, 
                    confidence="LOW", 
                    metadata={"prefix": prefix, "attribute": methodName}
                )

        return ResolvedSymbol(globalName=None, kind=ResolutionKind.unknown, confidence="LOW")