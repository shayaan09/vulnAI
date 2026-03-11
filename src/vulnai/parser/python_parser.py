import ast

#Will go into the file we grab from the cli.py and reads the contents, then converts them into code and returns the AST for that code
def fileToCode(fileName: str):
    with open(fileName, 'r', encoding="utf-8") as fileObj:
        fileContent = fileObj.read()
    
    codeTree = ast.parse(fileContent)
    return codeTree

class treeWalk(ast.NodeVisitor):
    def __init__(self):
        self.assignments = []
    

    #Will go through assignment 'styles' that aren't leaf assignments like simple assignment or a subscript assignment
    #It'll then recursively keep traversing into their subtrees until it reaches the leaves.
    def targetExtractor(self, node, nodeVal):
        if(isinstance(node, ast.Name)):
            self.assignment = {
                "nodeType": "Name",
                "target": node.id,
                "valNode": nodeVal
            }
            self.assignments.append(self.assignment)
            return

        elif(isinstance(node, ast.Tuple) or isinstance(node, ast.List)):
            elemList = node.elts
            for elem in elemList:
                self.targetExtractor(elem, nodeVal)

        elif(isinstance(node, ast.Subscript)):
            self.assignment = {
                "nodeType": "Subscript",
                "target": node.value,
                "slice": node.slice,
                "valNode": nodeVal
            }
            self.assignments.append(self.assignment)


        elif(isinstance(node, ast.Attribute)):
            self.assignment = {
                "nodeType": "Attribute",
                "target": node.value,
                "attribute": node.attr,
                "valNode": nodeVal
            }
            self.assignments.append(self.assignment)

            
        elif(isinstance(node, ast.Starred)):
            self.targetExtractor(node.value, nodeVal)

    def visit_Assign(self, node):
        left = node.targets #This is a list of nodes
        right = node.value #This is a subtree. Since an assignment can have a bunch of nodes inside it as well

        for target in left:
            self.targetExtractor(target, right)


        self.generic_visit(node)
            
"Further refined targetExtractor to assign the 'right' side of a var assignment. This will allow for storing the value insie the dict. targetExtractor() now expects 2 parameters. A node's value obj and the target obj are both on the same hierarchical level, so we can safely pass right as a param, regardless of how deep the recursion needs to go to extract the target names. This is not complete, and will break for tuples, augmented assignments, annotated assignments and chained assignments."