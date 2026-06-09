from dataclasses import dataclass
import ast

@dataclass(frozen=True)
class Definition:
    id: int
    var: str
    node: ast.stmt
