#Just a file where I can analyze different types of ASt structures for different nodes



import ast

node = ast.parse("x, y = 1, 2")
node2 = ast.parse("x = 1")
print(ast.dump(node, indent=4))
print(ast.dump(node2, indent=4))