import ast
from pathlib import Path
T=(Path(__file__).parents[1]/'app'/'main.py').read_text()

def probe():
    a=T.index('async def _probe_falco() -> dict:')
    b=T.index('\nasync def _probe_trivy',a)
    return T[a:b]

def test_parse(): ast.parse(T)
def test_quiet_state():
    P=probe()
    assert 'webhook_recent' in P
    assert 'if webhook_recent:' in P
    assert '"status":"quiet"' in P
def test_down_state():
    assert '"status":"down"' in probe()
def test_ui_label():
    assert "status==='quiet'?'QUIET'" in T
    assert "${label}" in T
def test_previous_fixes():
    assert '_sensor_heartbeat_set("falco"' in T
    assert 'asyncio.create_task(_falco_background_decision' in T
    assert '"accepted": True' in T
