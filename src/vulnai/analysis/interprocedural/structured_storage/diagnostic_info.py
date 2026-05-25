from dataclasses import dataclass


#Something went wrong while scanning, but vulnAI should not crash. Stores syntax errors and parsing issues without stopping execution, like def hello( shouldn't crash the entire scan
@dataclass
class DiagnosticInfo:
    filePath: str
    lineno: int
    severity: str #CRITICAL - The whole scan cannot continue., WARNING - Analysis can continue but may be incomplete, INFO, ERROR - A specific file/module/function couldn't be analyzed properly.
    message: str