# #Just a file where I can analyze different types of ASt structures for different nodes



import ast

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

def randoFunc2(x, y, z):
    while(x < 2 and y < 3 and z == 4):
        x += 1
        y += 1
        z = 4
    
    return x