import ast
from pathlib import Path

SRC=Path(__file__).parents[1]/"app"/"main.py"
TEXT=SRC.read_text()

def test_python_parses():
    ast.parse(TEXT)

def test_portainer_source_of_truth_helpers_present():
    for name in (
        "_compose_identity",
        "_resolve_portainer_stack",
        "_portainer_redeploy",
        "_observe_container_after_stack_update",
    ):
        assert f"def {name}" in TEXT or f"async def {name}" in TEXT

def test_redeploy_preserves_compose_text():
    # The patch deliberately sends snapshot compose text directly back to Portainer.
    assert '"stackFileContent":compose_text' in TEXT
    assert '"pullImage":bool(pull_image)' in TEXT
    assert '"prune":False' in TEXT

def test_rollback_uses_saved_compose():
    assert "automatic_rollback_portainer" in TEXT
    assert "_portainer_redeploy(stack_meta,compose_text,pull_image=False)" in TEXT

def test_stack_auto_mapping_labels():
    assert "com.docker.compose.project" in TEXT
    assert "com.docker.compose.service" in TEXT
