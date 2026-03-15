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
        self.functions = []
        self.classes = []
    

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
        
    def visit_FunctionDef(self, node):
        funcName = node.name
        funcLine = node.lineno
        argList = []

        #Args that have lists
        args = node.args.args
        posonlyargs = node.args.posonlyargs
        kwonlyargs = node.args.kwonlyargs
        
        #No-list args
        vararg = node.args.vararg
        kwarg = node.args.kwarg


        for arg in args:
            argList.append({
                "name": arg.arg,
                "argType": "regular"
            })

        for arg in posonlyargs:
            argList.append({
                "name": arg.arg,
                "argType": "posonlyarg"
            })
        
        for arg in kwonlyargs:
            argList.append({
                "name": arg.arg,
                "argType": "kwonlyarg"
            })
        

        
        if vararg:
            argList.append({
                "name": vararg.arg,
                "argType": "vararg"
            })
        
        if kwarg:
            argList.append({
                "name": kwarg.arg,
                "argType": "kwarg"
            })
        
        

        self.functions.append({
            "name": funcName,
            "arguments": argList,
            "line": funcLine
        })
        
        self.generic_visit(node)


    def visit_ClassDef(self, node):
        className = node.name
        baseList = []
        keywordList = []
        bodyNodeList = []
        classLine = node.lineno


        for base in node.bases:
            if isinstance(base, ast.Name):
                baseList.append({
                    "value": base.id,
                    "attribute": None
                })
            elif(isinstance(base, ast.Attribute)):
                baseList.append({
                    "value": base.value, #this will only give the node's memory address
                    "attribute": base.attr
                })
        
        for keyword in node.keywords:
            keywordList.append({
                "arg": keyword.arg,
                "value": keyword.value
            })
        
        for bodyNode in node.body:
            bodyNodeList.append({
                "nodeType": bodyNode
            })
        
        self.classes.append({
            "className": className,
            "bases": baseList,
            "keywords": keywordList,
            "bodyNodes": bodyNodeList,
            "line": classLine
        })

        
        self.generic_visit(node)
