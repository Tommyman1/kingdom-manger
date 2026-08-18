import ast
from pathlib import Path
T=(Path(__file__).parents[1]/'app'/'main.py').read_text()
TREE=ast.parse(T)
def test_timezone_imported():
    assert any(isinstance(n,ast.ImportFrom) and n.module=='datetime' and any(a.name=='timezone' for a in n.names) for n in TREE.body)
def test_backup_timestamp():
    assert 'datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")' in T
def test_backup_path():
    assert 'create_preupdate_backup' in T and 'Enable + Back Up' in T
