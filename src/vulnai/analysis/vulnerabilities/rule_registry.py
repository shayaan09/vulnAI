from collections import defaultdict
from vulnai.analysis.vulnerabilities.vulns import VulnerabilityRule

class RuleRegistry:
    def __init__(self, rules: list[VulnerabilityRule]):

        #Filter down to only dataflow rules
        self.taintRules: list[VulnerabilityRule] = [rule for rule in rules if rule.detectionType == "taintFlow"]
        self.patternRules: list[VulnerabilityRule] = [rule for rule in rules if rule.detectionType == "patternBased"]

        #type of source/sink/sanitizer -> set of CWE IDs
        self.sourceToCwes: dict[str, set[str]] = defaultdict(set)
        self.sinkToCwes: dict[str, set[str]] = defaultdict(set)
        self.sanitizerToCwes: dict[str, set[str]] = defaultdict(set)
        
        self.populateMaps()


    #Populates the maps
    def populateMaps(self) -> None:
        for rule in self.taintRules:

            #A rule's identifier for multi-taint tracking will be its CWE ID
            cweId = rule.cwe
            
            for source in rule.sources:
                self.sourceToCwes[source].add(cweId)
                
            for sink in rule.sinks:
                self.sinkToCwes[sink].add(cweId)
                
            for sanitizer in rule.sanitizers:
                self.sanitizerToCwes[sanitizer].add(cweId)


    def getSourceCwes(self, name: str) -> set[str]:
        return self.sourceToCwes.get(name, set())

    def getSinkCwes(self, name: str) -> set[str]:
        return self.sinkToCwes.get(name, set())

    def getSanitizerCwes(self, name: str) -> set[str]:
        return self.sanitizerToCwes.get(name, set())

    #Checks if the name we're processing is in any of our lists
    def isTrackedAnywhere(self, name: str) -> bool:
        return name in self.sourceToCwes or name in self.sinkToCwes or name in self.sanitizerToCwes
