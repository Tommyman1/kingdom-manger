import ast,re
from pathlib import Path
T=(Path(__file__).parents[1]/'app'/'main.py').read_text()

def test_parse():
    ast.parse(T)

def test_background_wrapper():
    assert 'async def _falco_background_decision' in T
    assert 'await decision_for_security' in T

def test_endpoint_schedules_background_work():
    m=re.search(r'@app\.post\("/api/security/falco"\).*?(?=\n@app\.)',T,re.S)
    assert m
    block=m.group(0)
    assert 'asyncio.create_task(_falco_background_decision' in block
    assert 'await decision_for_security' not in block

def test_core_dashboard_survives():
    for x in ['function renderWarmScore','async function act','async function scan','async function openDrawer','async function fixWhatKingdomCan']:
        assert x in T
