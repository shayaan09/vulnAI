from collections import defaultdict
from vulnai.analysis.vulnerabilities.vulns import VulnerabilityRule
from fnmatch import fnmatchcase

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
        for rule in self.taintRules + self.patternRules:

            #A rule's identifier for multi-taint tracking will be its CWE ID
            cweId = rule.cwe
            
            for source in rule.sources:
                self.sourceToCwes[source].add(cweId)
                
            for sink in rule.sinks:
                self.sinkToCwes[sink].add(cweId)
                
            for sanitizer in rule.sanitizers:
                self.sanitizerToCwes[sanitizer].add(cweId)


    #table is either sourceToCwes, sinkToCwes, or sanitizerToCwes
    def _lookup(self, table: dict[str, set[str]], name: str | None) -> set[str]:
            if not name:
                return set()
            
            #Exact matching to the src/sink/sanitizer list. This is the exact dictionairy lookup
            hits = set(table.get(name, set()))

            for pattern, cwes in table.items():
                if pattern == name:
                    continue
                
                #wildcard rule match
                if "*" in pattern and fnmatchcase(name, pattern):
                    hits.update(cwes)

                #Allows rules like "execute" to match "cursor.execute". Basically a suffix match lol
                elif "." not in pattern and name.endswith("." + pattern):
                    hits.update(cwes)

            return hits
    


    def getSourceCwes(self, name: str) -> set[str]:
        return self._lookup(self.sourceToCwes, name)

    def getSinkCwes(self, name: str) -> set[str]:
        return self._lookup(self.sinkToCwes, name)

    def getSanitizerCwes(self, name: str) -> set[str]:
        return self._lookup(self.sanitizerToCwes, name)

    #Checks if the name we're processing is in any of our lists
    def isTrackedAnywhere(self, name: str) -> bool:
        return bool(self.sourceToCwes or name in self.sinkToCwes or name in self.sanitizerToCwes)
