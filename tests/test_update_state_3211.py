import ast,re
from pathlib import Path
T=(Path(__file__).parents[1]/'app'/'main.py').read_text()
def test_parse(): ast.parse(T)
def test_apply_accepts_risk_reduction():
    i=T.find('async def update_apply')
    block=T[i:i+5000]
    assert 'verified-risk-reduction' in block
def test_approval_route_still_present():
    assert 'approve-risk-reduction' in T
def test_normal_verified_still_present():
    i=T.find('async def update_apply')
    block=T[i:i+5000]
    assert "'verified'" in block or '"verified"' in block
def test_core_survives():
    for x in ['function renderWarmScore','async function act','async function scan','async function openDrawer','async function fixWhatKingdomCan']:
        assert x in T
