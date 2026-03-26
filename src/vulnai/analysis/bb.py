import ast
from dataclasses import dataclass, field


@dataclass
class BasicBlock:
    id: int
    statements: list[ast.stmt] = field(default_factory=list)
    prevBlocks: list["BasicBlock"] = field(default_factory=list)
    nextBlocks: list["BasicBlock"] = field(default_factory=list)


