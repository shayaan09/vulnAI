from dataclasses import dataclass
from typing import Optional

@dataclass
class ImportInfo:
    moduleName: str            #The source module being imported from.  from db import runQuery, moduleNamwe stores db
    importedName: Optional[str | None] #The exact thing imported from the module. from db import runQuery, importedName stores runQuery()
    alias: Optional[str]
    kind: str                   #Structural category: literal "import" or "from_import"
    lineno: int