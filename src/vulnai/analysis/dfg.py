import ast

class TaintAnalyzer:
    def __init__(self):
        self.taintedVars = set()
        self.tOList = {"request", "argv", "environ", "input"} #tainted origin list. contains all types of origins that have potential to be tainted
        self.tSList = {"execute", "raw", "execute_many", "read_sql", "execute_sql"} #tainted sink list, same design choice as tOList

    def ruleEnforce(self, node, rhsv, lhsv): #rhsv = right hand side variable

        if(isinstance(node, ast.Call)):
            if(isinstance(node.func, ast.Name) and node.func.id in self.tSList):
                for arg in node.args:

                    if((isinstance(arg, ast.Name) and arg.id in self.taintedVars)): #needs to be changed to handle all types of assignments. not just simple assignments
                        print(f"Vulnerability Found: {arg.id} is a tainted variable")

            elif(isinstance(node.func, ast.Attribute) and node.func.attr in self.tSList):

                for arg in node.args:
                    if((isinstance(arg, ast.Name) and arg.id in self.taintedVars)):
                        print(f"Vulnerability Found: {arg.id} is a tainted variable")

              


        if rhsv in self.taintedVars or rhsv in self.tOList:
            self.taintedVars.add(lhsv)
        



