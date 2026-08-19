import ast,re
from pathlib import Path
T=(Path(__file__).parents[1]/'app'/'main.py').read_text()
def test_parse(): ast.parse(T)
def test_heartbeat_helpers():
    assert 'def _sensor_heartbeat_set' in T and 'def _sensor_heartbeat_get' in T
def test_webhook_updates_heartbeat():
    m=re.search(r'@app\.post\("/api/security/falco"\).*?(?=\n@app\.)',T,re.S)
    assert m and '_sensor_heartbeat_set("falco"' in m.group(0)
def test_probe_accepts_fresh_webhook():
    i=T.find('async def _probe_falco')
    b=T[i:i+2500]
    assert 'webhook_fresh' in b and '"source":"webhook"' in b
def test_summary_fields():
    assert '"last_webhook_ts"' in T and '"webhook_connected"' in T
def test_fast_ack_still_present():
    assert 'asyncio.create_task(_falco_background_decision' in T
