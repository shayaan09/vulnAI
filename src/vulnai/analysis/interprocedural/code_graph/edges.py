from dataclasses import dataclass, field
from typing import Dict, Any



@dataclass
class GraphEdge:
    source: str             #node where the edge starts. Source node ID
    target: str             #node where the edge points. Target node ID
    edgeType: str               # "CONTAINS" / "IMPORTS" / "CALLS"
    metadata: Dict[str, Any] = field(default_factory=dict)

