import ast
from pathlib import Path
T=(Path(__file__).parents[1]/'app'/'main.py').read_text()
def test_parse(): ast.parse(T)
def test_create_json_body():
    assert '"POST","/containers/create"' in T
    assert 'ok=(201,)' in T
    assert 'json=payload' in T
def test_docker_status_codes():
    assert '/start",ok=(204,)' in T
    assert '?force=1",ok=(204,)' in T
def test_persistent_destination_resolved():
    assert 'SELF_CONTAINER_NAME' in T
    assert 'm.get("Destination")=="/data"' in T
    assert "self_data['Source']" in T
def test_source_mounts_readonly():
    assert 'binds.append(f"{m[\'Source\']}:{hp}:ro")' in T
def test_core_ui_survives():
    for x in ['function renderWarmScore','async function act','async function scan','async function openDrawer','async function fixWhatKingdomCan']:
        assert x in T
