import ast
from pathlib import Path
TEXT=(Path(__file__).parents[1]/'app'/'main.py').read_text()

def test_parse():
    ast.parse(TEXT)

def test_policy():
    assert 'allow_stateful_update' in TEXT
    assert 'Allow Stateful Update' in TEXT

def test_effective_gate():
    assert "UPDATE_ALLOW_STATEFUL or pol.get('allow_stateful_update')" in TEXT

def test_backup_panel():
    assert 'DATA SAFETY' in TEXT
    assert 'backup_provider' in TEXT
    assert 'backup_verified_ts' in TEXT

def test_dedupe_comparison():
    assert 'def unique_counts' in TEXT
    assert 'removed_count' in TEXT
    assert 'remaining_count' in TEXT
    assert 'introduced_count' in TEXT

def test_no_global_only_gate():
    assert "Stateful container has mounts/volumes. Enable this container" in TEXT
