import ast
from pathlib import Path
TEXT=(Path(__file__).parents[1]/'app'/'main.py').read_text()

def test_python_parse():
    ast.parse(TEXT)

def test_dialog_html_support():
    assert "html=''" in TEXT
    assert "textEl.innerHTML=html" in TEXT
    assert "km-modal-wide" in TEXT

def test_adjacent_dashboard_functions_survive():
    for fn in [
        'function renderWarmScore',
        'async function act',
        'async function scan',
        'async function openDrawer',
        'async function fixWhatKingdomCan',
        'async function showVulnerabilities',
        'async function load',
    ]:
        assert fn in TEXT, fn

def test_remediation_ui_survives():
    assert 'Fix What Kingdom Can' in TEXT
    assert 'View All Issues' in TEXT
    assert 'remediationComparisonHtml' in TEXT

def test_security_sensor_logic_survives():
    assert 'async def _probe_falco' in TEXT
    assert 'async def _probe_trivy' in TEXT
    assert 'async def _probe_clamav' in TEXT
    assert 'async def _probe_crowdsec' in TEXT
