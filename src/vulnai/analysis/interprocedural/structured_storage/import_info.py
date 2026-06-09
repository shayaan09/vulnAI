from dataclasses import dataclass

@dataclass
class ImportInfo:
    moduleName: str            #The source module being imported from.  from db import runQuery, moduleNamwe stores db
    importedName: str | None #The exact thing imported from the module. from db import runQuery, importedName stores runQuery()
    alias: str | None
    kind: str                   #Structural category: literal "import" or "from_import"
    lineno: int