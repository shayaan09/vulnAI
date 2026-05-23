import ast
from vulnai.analysis.cfg import ControlFlowGraph as cfg
from vulnai.analysis.builder import Builder
from vulnai.analysis.reachingdef import ReachingDefinitionAnalyzer
from vulnai.analysis.usedef import UseDefAnalyzer
from vulnai.analysis.dfg_edge import DataFlowGraph as dfg
from vulnai.analysis.dfg import TaintAnalyzer

from vulnai.analysis.vulnerabilities.command_injection import COMMAND_RULE
from vulnai.analysis.vulnerabilities.hardcoded_secrets import HARDCODED_SECRETS_RULE
from vulnai.analysis.vulnerabilities.insecure_deserialization import INSECURE_DESERIALIZATION_RULE
from vulnai.analysis.vulnerabilities.path_traversal import PATH_TRAVERSAL_RULE
from vulnai.analysis.vulnerabilities.insecure_random import INSECURE_RANDOM_RULE
from vulnai.analysis.vulnerabilities.sqli import SQLI_RULE
from vulnai.analysis.vulnerabilities.ssrf import SSRF_RULE
from vulnai.analysis.vulnerabilities.weak_cryptography import WEAK_CRYPTOGRAPHY_RULE
from vulnai.analysis.vulnerabilities.xss import XSS_RULE
from vulnai.analysis.vulnerabilities.xxe import XXE_RULE


ALL_RULES = [
    SQLI_RULE,
    COMMAND_RULE,
    PATH_TRAVERSAL_RULE,
    XSS_RULE,
    INSECURE_DESERIALIZATION_RULE,
    HARDCODED_SECRETS_RULE,
    WEAK_CRYPTOGRAPHY_RULE,
    INSECURE_RANDOM_RULE,
    SSRF_RULE,
    XXE_RULE,
]

TEST_CODE = """
import os
import pickle
import random
import hashlib
import requests
import xml.etree.ElementTree as ET

user_id = input("Enter user id: ")
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)

cmd = input("Enter command: ")
os.system(cmd)

filename = input("Enter filename: ")
file_data = open(filename, "r")

comment = input("Enter comment: ")
html = "<p>" + comment + "</p>"
return_html(html)

serialized = input("Enter serialized data: ")
obj = pickle.loads(serialized)

api_key = "sk_test_123456789SECRET"
password = "admin123"

value = input("Enter value: ")
hashed = hashlib.md5(value.encode()).hexdigest()

token = random.random()

url = input("Enter URL: ")
response = requests.get(url)

xml_data = input("Enter XML: ")
root = ET.fromstring(xml_data)
"""


tree = ast.parse(TEST_CODE)

builder = Builder()
cfg = builder.cfgBuild(tree.body)

rda = ReachingDefinitionAnalyzer()

for block in cfg.blocks:
    rda.defCollect(block)

for block in cfg.blocks:
    rda.defHandle(block)

rda.transferFunction(cfg)

uda = UseDefAnalyzer()
uda.analyze(cfg, rda)

taintAnalyzer = TaintAnalyzer(uda, rda)

print("\\n========== RUNNING WEEK 4 SECURITY RULE TESTS ==========")

totalDetected = 0

for rule in ALL_RULES:
    print(f"\\n--- Testing Rule: {rule.name} [{rule.cwe}] ---")

    if rule.detectionType == "taintFlow":
        found = taintAnalyzer.flowRun(cfg, rule)

    elif rule.detectionType == "patternBased":
        found = taintAnalyzer.patternRun(cfg, rule)

    else:
        print(f"Unknown detection type: {rule.detectionType}")
        found = False

    if found:
        totalDetected += 1

print("\\n========== TEST SUMMARY ==========")
print(f"Rules triggered: {totalDetected}/{len(ALL_RULES)}")
