import ast
from dataclasses import dataclass, field
from vulnai.analysis.definition import Definition

@dataclass
class BasicBlock:
    id: int
    statements: list[ast.stmt] = field(default_factory=list)
    prevBlocks: list["BasicBlock"] = field(default_factory=list)
    nextBlocks: list["BasicBlock"] = field(default_factory=list)
    GEN: set[Definition] = field(default_factory=set)
    KILL: set[Definition] = field(default_factory=set)
    IN: set[Definition] = field(default_factory=set)
    OUT: set[Definition] = field(default_factory=set)
    definitions: list[Definition] = field(default_factory=list)

    


