import ast,re
from pathlib import Path
T=(Path(__file__).parents[1]/'app'/'main.py').read_text()

def test_parse():
    ast.parse(T)

def test_webhook_does_not_return_task():
    m=re.search(r'@app\.post\("/api/security/falco"\).*?(?=\n@app\.)',T,re.S)
    assert m
    block=m.group(0)
    assert 'return asyncio.create_task' not in block
    assert 'asyncio.create_task(_falco_background_decision' in block

def test_webhook_returns_json_ack():
    m=re.search(r'@app\.post\("/api/security/falco"\).*?(?=\n@app\.)',T,re.S)
    block=m.group(0)
    assert '"accepted": True' in block
    assert '"sensor": "falco"' in block

def test_heartbeat_still_written():
    assert '_sensor_heartbeat_set("falco"' in T

def test_probe_still_uses_webhook_freshness():
    i=T.find('async def _probe_falco')
    assert 'webhook_fresh' in T[i:i+2500]

def test_core_ui_survives():
    for x in ['function renderWarmScore','async function openDrawer','async function fixWhatKingdomCan']:
        assert x in T
