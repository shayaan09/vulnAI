# #Just a file where I can analyze different types of ASt structures for different nodes





# node = ast.parse("x, y = 1, 2")
# node2 = ast.parse("x = 1")
# #print(ast.dump(node, indent=4))
# #print(ast.dump(node2, indent=4))


# node3 = ast.parse('l[1:2, 3] = y')
# #print(ast.dump(node3,  indent=4))

# node4 = ast.parse('snake.colour = w')
# #print(ast.dump(node4, indent=4))

# node5 = ast.parse('def func(a,b): return 0')
# #print(ast.dump(node5, indent =4))


# def randoFuncToVisualizeCFG(x = 0, y = 0, z = 0):
#     if x == 0:
#         x + 1
#     elif y==0:
#         y + 1
#     else:
#         z + 1

#     return x

# def randoFunc2(x, y, z):
#     while(x < 2 and y < 3 and z == 4):
#         x += 1
#         y += 1
#         z = 4
    
#     return x

import ast

from vulnai.analysis.builder import Builder
from vulnai.analysis.reachingdef import ReachingDefinitionAnalyzer
from vulnai.analysis.usedef import UseDefAnalyzer
from vulnai.analysis.dfg_edge import DataFlowGraph
from vulnai.analysis.dfg import TaintAnalyzer
from vulnai.analysis.vulnerabilities.command_injection import COMMAND_RULE
from vulnai.analysis.vulnerabilities.hardcoded_secrets import HARDCODED_SECRETS_RULE
from vulnai.analysis.vulnerabilities.insecure_deserialization import INSECURE_DESERIALIZATION_RULE
from vulnai.analysis.vulnerabilities.path_traversal import PATH_TRAVERSAL_RULE
from vulnai.analysis.vulnerabilities.insecure_random import INSECURE_RANDOM_RULE
from vulnai.analysis.vulnerabilities.sqli import SQLI_RULE
from vulnai.analysis.vulnerabilities.ssrf import SSRF_RULE
from vulnai.analysis.vulnerabilities.weak_cryptography import WEAK_CRYPTOGRAPHY_RULE
from vulnai.analysis.vulnerabilities.xss import XSS_Rule
from vulnai.analysis.vulnerabilities.xxe import XXE_RULE

# source = """
# x = 0
# while cond:
#     x = x + 1
# y = x
# """

# tree = ast.parse(source)

# builder = Builder()
# cfg = builder.cfgBuild(tree.body)
# reachingAnalyzer = ReachingDefinitionAnalyzer()

# for block in cfg.blocks:
#     reachingAnalyzer.defCollect(block)

# for block in cfg.blocks:
#     reachingAnalyzer.defHandle(block)

# reachingAnalyzer.transferFunction(cfg)

# useDefAnalyzer = UseDefAnalyzer()
# useDefAnalyzer.analyze(cfg, reachingAnalyzer)

# dfg = DataFlowGraph()
# dfg.buildFromUseDefEdges(useDefAnalyzer.useDefEdges)


# for block in cfg.blocks:
#     print(f"\nBlock {block.id}")

#     print("Statements:")
#     for stmt in block.statements:
#         print("  ", ast.unparse(stmt))

#     print("GEN:")
#     for d in block.GEN:
#         print("  ", d.id, d.var, "=", ast.unparse(d.node))

#     print("KILL:")
#     for d in block.KILL:
#         print("  ", d.id, d.var, "=", ast.unparse(d.node))

#     print("IN:")
#     for d in block.IN:
#         print("  ", d.id, d.var, "=", ast.unparse(d.node))

#     print("OUT:")
#     for d in block.OUT:
#         print("  ", d.id, d.var, "=", ast.unparse(d.node))


# print("\nUSE-DEF EDGES")
# for useStmt in useDefAnalyzer.useDefEdges:
#     print(f"\nUSE STMT: {ast.unparse(useStmt)}")

#     for definition in useDefAnalyzer.useDefEdges[useStmt]:
#         print(f"  reached by: {definition.id} {definition.var} = {ast.unparse(definition.node)}")


# print("\nDFG EDGES")
# for edge in dfg.edges:
#     print(f"{ast.unparse(edge.source)}  --->  {ast.unparse(edge.target)}")


code_string = "x = input().strip()"
tree = ast.parse(code_string, mode='exec')

print(ast.dump(tree, indent=4))