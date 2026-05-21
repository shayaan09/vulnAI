from dataclasses import dataclass, field
from enum import Enum


@dataclass
class VulnerabilityRule:
    name: str #what vuln this is
    cwe: str #CWE-ID
    detectionType: str #Two options: taintFlow or patternBased, since not every vuln uses data flow to exploit

    sources: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)
    sanitizers: list[str] = field(default_factory=list) #something that makes dangerous/untrusted input safe before it reaches a dangerous operation
