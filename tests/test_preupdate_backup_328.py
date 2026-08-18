import ast
from pathlib import Path
T=(Path(__file__).parents[1]/'app'/'main.py').read_text()
def test_parse(): ast.parse(T)
def test_import(): assert '\nimport re\n' in T
def test_stream_hash(): assert 'for chunk in iter(lambda: fh.read(1024*1024), b"")' in T
def test_endpoint(): assert '/api/containers/{name}/preupdate-backup' in T and 'detail=result' in T
def test_ui(): assert 'Enable + Back Up' in T and 'Back Up Now' in T
def test_core():
    for x in ['function renderWarmScore','async function act','async function scan','async function openDrawer','async function fixWhatKingdomCan']:
        assert x in T
