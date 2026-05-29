from dataclasses import dataclass, field
from typing import Dict, List
from vulnai.analysis.interprocedural.code_graph.edges import GraphEdge
from vulnai.analysis.interprocedural.code_graph.nodes import GraphNode

#Actual graph container

#REASON FOR MAKING INCOMING AND OUTGOING IN CodeGraph AND NOT IN GraphNode

# GraphNode should be a lightweight, immutable "dumb record." 
# Its only job is to store properties about a specific piece of code (its type, line number, 
# and a reference pointer back to the source code).

# If a node starts managing its own connectivity states, 
# traversing the graph means you are constantly modifying the internal states of your data records. 
# By pulling the connections out into outgoing and incoming maps inside CodeGraph, the nodes stay pure, metadata-only records, 
# and the graph container handles the math of network relationships. Otherwise, it will make memory use explode.

@dataclass
class CodeGraph:
    nodes: Dict[str, GraphNode] = field(default_factory=dict) #node id -> GraphNode. stores all nodes
    edges: List[GraphEdge] = field(default_factory=list) #stores all edges
    outgoing: Dict[str, List[GraphEdge]] = field(default_factory=dict) #node id -> A list of Edges leaving it
    incoming: Dict[str, List[GraphEdge]] = field(default_factory=dict) #node id -> A list of Edges landing on it

    def addNode(self, node: GraphNode):

        self.nodes[node.id] = node

        #When creating a node, completely isolate it until CodeGraphBuilder and CallgraphBuilder use it to connect to the rest of the graph
        if node.id not in self.outgoing:
            self.outgoing[node.id] = []

        if node.id not in self.incoming:
            self.incoming[node.id] = []

    #Checks if both the start-point and end-point nodes actually exist in the graph
    def addEdge(self, edge: GraphEdge) -> bool:
        if edge.source not in self.nodes or edge.target not in self.nodes:
            return False
            
        self.edges.append(edge)
        self.outgoing[edge.source].append(edge)
        self.incoming[edge.target].append(edge)
        return True