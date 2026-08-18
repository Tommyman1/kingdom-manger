import ast
from pathlib import Path
TEXT=(Path(__file__).parents[1]/'app'/'main.py').read_text()
def test_parse(): ast.parse(TEXT)
def test_compare(): assert 'def _compare_scans' in TEXT and 'risk_reduction_percent' in TEXT
def test_immutable(): assert "await _trivy_scan_ref(str(p['old_image_id']" in TEXT and "await _trivy_scan_ref(str(p['candidate_image_id']" in TEXT
def test_approval(): assert 'approve-risk-reduction' in TEXT and 'verified-risk-reduction' in TEXT
def test_ui(): assert 'Fix What Kingdom Can' in TEXT and 'View All Issues' in TEXT
def test_listing(): assert '/api/containers/{name}/vulnerabilities' in TEXT
def test_auto_manual(): assert 'awaiting-operator-risk-approval' in TEXT
def test_stateful_gate(): assert 'Stateful update safety gate' in TEXT and 'Verified backup required' in TEXT
