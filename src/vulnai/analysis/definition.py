from dataclasses import dataclass
import ast

@dataclass
class Definition:
    id: int
    var: str
    node: ast.stmt
