import ast

#Will go into the file we grab from the cli.py and reads the contents, then converts them into code and returns the AST for that code
def fileToCode(fileName: str):
    with open(fileName, 'r', encoding="utf-8") as fileObj:
        fileContent = fileObj.read()
    
    codeTree = ast.parse(fileContent)
    return codeTree

class treeWalk(ast.NodeVisitor):
    def __init__(self):
        self.assignmentNames = []
    
    def visit_Assign(self, node):
        
