"""Tests for nvctl v5 CLI extensions — AI Security Platform."""
import json
import pytest
from click.testing import CliRunner

from nvctl.main import cli
from nvctl import config as cfg_module


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setattr(cfg_module, "CONFIG_DIR", tmp_path / ".nvctl")
    monkeypatch.setattr(cfg_module, "CONFIG_FILE", tmp_path / ".nvctl" / "config.json")
    monkeypatch.setattr(cfg_module, "CRED_FILE", tmp_path / ".nvctl" / "credentials.json")
    return tmp_path


def test_ai_group_exists():
    runner = CliRunner()
    result = runner.invoke(cli, ["ai", "--help"])
    assert result.exit_code == 0
    for cmd in ["status", "health", "explain", "investigate", "search", "findings"]:
        assert cmd in result.output


def test_ai_status_command(isolated_home, monkeypatch):
    class FakeClient:
        def __init__(self): pass
        def get(self, path, **kw):
            return {"success": True, "data": {"enabled": False, "configured": False, "message": "AI_ENABLED is false"}}
    monkeypatch.setattr("nvctl.main.NVClient", FakeClient)
    runner = CliRunner()
    result = runner.invoke(cli, ["ai", "status"])
    assert result.exit_code == 0
    assert "Enabled: False" in result.output


def test_ai_status_json(isolated_home, monkeypatch):
    class FakeClient:
        def __init__(self): pass
        def get(self, path, **kw):
            return {"success": True, "data": {"enabled": True, "configured": True, "provider": "gemini", "model": "gemini-2.0-flash"}}
    monkeypatch.setattr("nvctl.main.NVClient", FakeClient)
    runner = CliRunner()
    result = runner.invoke(cli, ["ai", "status", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["data"]["provider"] == "gemini"


def test_ai_explain_success(isolated_home, monkeypatch):
    class FakeClient:
        def __init__(self): pass
        def post(self, path, body=None, **kw):
            return {"success": True, "data": {"success": True, "finding": {
                "summary": "test summary", "severity": "medium", "confidence": "high",
                "evidence": ["e1"], "explanation": ["i1"], "recommended_actions": ["a1"],
            }}}
    monkeypatch.setattr("nvctl.main.NVClient", FakeClient)
    runner = CliRunner()
    result = runner.invoke(cli, ["ai", "explain", "some-audit-id"])
    assert result.exit_code == 0
    assert "test summary" in result.output


def test_ai_explain_unavailable(isolated_home, monkeypatch):
    class FakeClient:
        def __init__(self): pass
        def post(self, path, body=None, **kw):
            return {"success": True, "data": {"success": False, "error": "AI disabled", "error_type": "unavailable"}}
    monkeypatch.setattr("nvctl.main.NVClient", FakeClient)
    runner = CliRunner()
    result = runner.invoke(cli, ["ai", "explain", "some-audit-id"])
    assert result.exit_code == 0
    assert "unavailable" in result.output


def test_ai_search_command(isolated_home, monkeypatch):
    class FakeClient:
        def __init__(self): pass
        def post(self, path, body=None, **kw):
            assert body["query"] == "show failed logins"
            return {"success": True, "data": {"success": True, "sources_queried": ["audit"]}}
    monkeypatch.setattr("nvctl.main.NVClient", FakeClient)
    runner = CliRunner()
    result = runner.invoke(cli, ["ai", "search", "show failed logins", "--json"])
    assert result.exit_code == 0


def test_ai_findings_command(isolated_home, monkeypatch):
    class FakeClient:
        def __init__(self): pass
        def get(self, path, **kw):
            return {"success": True, "data": [{"id": "f1", "summary": "test"}]}
    monkeypatch.setattr("nvctl.main.NVClient", FakeClient)
    runner = CliRunner()
    result = runner.invoke(cli, ["ai", "findings", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert len(data["data"]) == 1


def test_ai_investigate_command(isolated_home, monkeypatch):
    class FakeClient:
        def __init__(self): pass
        def post(self, path, body=None, **kw):
            assert body["question"] == "was this unusual"
            return {"success": True, "data": {"success": True}}
    monkeypatch.setattr("nvctl.main.NVClient", FakeClient)
    runner = CliRunner()
    result = runner.invoke(cli, ["ai", "investigate", "audit-id-1", "was this unusual", "--json"])
    assert result.exit_code == 0
