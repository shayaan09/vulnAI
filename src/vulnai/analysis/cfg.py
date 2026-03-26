import ast
from dataclasses import dataclass, field
from vulnai.analysis.bb import BasicBlock as bb

@dataclass
class ControlFlowGraph:
    blocks: list[bb] = field(default_factory=list)
    entryBlock: bb = field(init = False)
    exitBlock: bb = field(init = False)
    id: int = 0 #the id for the block created next

    def __post_init__(self):
        self.entryBlock = self.blockBuild()
        self.exitBlock = bb(-1) 
        self.blocks.append(self.exitBlock)

    def blockBuild(self) -> bb:
        block = bb(self.id)
        self.id += 1
        self.blocks.append(block)

        return block
    
    def blockConnector(self, prevB: bb, nextB: bb):
        prevB.nextBlocks.append(nextB)
        nextB.prevBlocks.append(prevB)




    



