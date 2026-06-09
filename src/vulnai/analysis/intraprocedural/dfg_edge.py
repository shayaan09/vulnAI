import ast
from vulnai.analysis.intraprocedural.definition import Definition


class DFGEdge:
    source: ast.AST          #definition.node
    target: ast.AST          #stmt where the use happens
    definition: Definition   


class DataFlowGraph:
    def __init__(self):
        self.edges: list[DFGEdge] = []

    def buildFromUseDefEdges(self, useDefEdges):
        for useStmt in useDefEdges:
            reachingDefs = useDefEdges[useStmt]

            for definition in reachingDefs:
                edge = DFGEdge()
                edge.source = definition.node
                edge.target = useStmt
                edge.definition = definition

                self.edges.append(edge)