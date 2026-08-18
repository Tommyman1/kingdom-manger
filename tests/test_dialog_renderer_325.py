import ast
from pathlib import Path
TEXT=(Path(__file__).parents[1]/'app'/'main.py').read_text()

def test_python_parses():
    ast.parse(TEXT)

def test_html_supported():
    assert "if(html)" in TEXT
    assert "content.innerHTML=html" in TEXT

def test_text_fallback():
    assert "content.textContent=text" in TEXT

def test_wide_supported():
    assert "wide?' wide':''" in TEXT
    assert ".km-dialog-card.wide" in TEXT

def test_remediation_uses_html():
    assert "html:panel" in TEXT

def test_dialog_body_not_title_only():
    assert "body.append(heading,content,actions)" in TEXT
