from typing import Dict, Optional
from dataclasses import dataclass, field


#Keeps track of a func's behavior (which parameters trigger sinks, what returns are tainted)
@dataclass
class FunctionSummary:
    functionName: str  #fully qualified funcname
    returnsTainted: bool = False #boolean flag. If this is True, the interprocedural analyzer knows that any call to this function returns tainted data, regardless of what inputs were passed. The func creates the taint itself
    directSourceReturn: Optional[str] = None #stores which source caused the tainted return
    
    #It only returns taint if parameter x was already bad when passed into the params, otherwise the function is safe
    taintedReturnParams: set = field(default_factory=set)
    paramsToSinks: Dict[str, list] = field(default_factory=dict) #param name -> sinks that param can reach
    sinkCalls: list = field(default_factory=list) #records all sink calls found in the function


#Stores FunctionSummary info so that phase 2 can look up security behaviour of any func extremely quickly. Avoids the need to re-parse files again and again
class SummaryStore:
    def __init__(self):
        self._store: Dict[str, FunctionSummary] = {}

    def addSummary(self, summary: FunctionSummary):
        self._store[summary.functionName] = summary

    def getSummary(self, functionName: str) -> Optional[FunctionSummary]:
        return self._store.get(functionName)