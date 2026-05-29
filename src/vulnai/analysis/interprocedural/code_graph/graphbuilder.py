from vulnai.analysis.interprocedural.structured_storage.codebase_index import CodebaseIndex
from vulnai.analysis.interprocedural.code_graph.edges import GraphEdge
from vulnai.analysis.interprocedural.code_graph.nodes import GraphNode
from vulnai.analysis.interprocedural.code_graph.graph import CodeGraph


class CodeGraphBuilder:
    def __init__(self):
        self.typeModule = "MODULE"
        self.typeFunction = "FUNCTION"
        self.typeContains = "CONTAINS"
        self.typeImports = "IMPORTS"

    def build(self, index: CodebaseIndex) -> CodeGraph:
        graph = CodeGraph()

        #Module handling
        for moduleName in index.modules.keys():
            nodeId = f"module:{moduleName}"
            node = GraphNode(id=nodeId, nodeType=self.typeModule, ref=moduleName)
            graph.addNode(node)

        #Function handling
        for globalName, funcData in index.functionTable.items():
            funcNodeId = f"function:{globalName}"
            funcNode = GraphNode(id=funcNodeId, nodeType=self.typeFunction, ref=globalName)
            graph.addNode(funcNode)

            parentModuleId = f"module:{funcData.moduleName}" #Computes what the ID of the file containing this function would be
            containsEdge = GraphEdge(source=parentModuleId, target=funcNodeId, edgeType=self.typeContains)
            graph.addEdge(containsEdge)

        #Project-specific, internal imports
        #Iterates through the importGraph map
        for sourceMod, targetSet in index.importGraph.items():
            sourceNodeId = f"module:{sourceMod}"
            
            #Iterates through the collection of strings that this specific file tried to import
            for targetMod in targetSet:
                targetNodeId = f"module:{targetMod}"
                
                if targetNodeId in graph.nodes:
                    importsEdge = GraphEdge(source=sourceNodeId, target=targetNodeId, edgeType=self.typeImports)
                    graph.addEdge(importsEdge)

        return graph