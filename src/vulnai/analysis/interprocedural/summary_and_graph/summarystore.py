from dataclasses import dataclass, field
from collections import defaultdict

#Keeps track of a func's behavior (which parameters trigger sinks, what returns are tainted)


@dataclass
class FunctionSummary:
    functionName: str  
    
    #cweId -> bool. True if the function unconditionally returns a direct/indirect source for that rule, like {"CWE-78": True, "CWE-79": False}
    returnsTainted: dict[str, bool] = field(default_factory=dict)  
    
    #cweId -> literal string name of the source that caused the tainted return, like: {"CWE-78": "input"}
    directSourceReturn: dict[str, str|None] = field(default_factory=dict)  
    
    #paramName -> set of cweIds. Answers: "Which input parameters can contaminate the func's return value"
    taintedReturnParams: dict[str, set[str]] = field(default_factory=dict)  
    
    #paramName -> {cweId -> list of sink calls}. Tracks which params hit which sinks per rule.     
    paramsToSinks: dict[str, dict[str, list[str]]] = field(default_factory=dict)  
    
    #Global record of EVERY sink call discovered anywhere in the function, it doesnt matter if it is tainted or not
    sinkCalls: list[str] = field(default_factory=list)  
    
    #Data log that stores which src hit a sink inside the func
    localVulnerabilities: list[dict] = field(default_factory=list)
    
    #Prevents the analyzer from generating duplicate error logs for the exact same vulnerability
    _reportedLocalSigs: set[tuple] = field(default_factory=set, repr=False)

    #Stores pattern based hardcoded vals like API keys
    bannedPatterns: list[dict] = field(default_factory=list)

    #Basically says: “Inside this function, these local variables are already known to be tainted because they came from a source.”
    # var -> set of cwes it may contain
    localSourceVars: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    # #local var X depends on param Y for Z CWE types. var -> param -> CWE set
    paramDependentVars: dict[str, dict[str, set[str]]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(set)))




#Stores FunctionSummary info so that phase 2 can look up security behaviour of any func extremely quickly. Avoids the need to re-parse files again and again
class SummaryStore:
    def __init__(self):
        self._store: dict[str, FunctionSummary] = {}

    def addSummary(self, summary: FunctionSummary):
        self._store[summary.functionName] = summary

    def getSummary(self, functionName: str) -> FunctionSummary | None:
        return self._store.get(functionName)