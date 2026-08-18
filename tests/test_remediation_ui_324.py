import ast
from pathlib import Path
TEXT=(Path(__file__).parents[1]/'app'/'main.py').read_text()
def test_parse(): ast.parse(TEXT)
def test_cards(): assert 'remediationComparisonHtml' in TEXT and 'remed-compare' in TEXT
def test_safety(): assert 'DATA SAFETY' in TEXT and 'data-safety-card' in TEXT
def test_impact(): assert 'Removed' in TEXT and 'Still present' in TEXT and 'New' in TEXT
def test_vuln_ui(): assert 'vuln-kpis' in TEXT and 'vuln-row-head' in TEXT
def test_mobile(): assert '@media(max-width:720px)' in TEXT
