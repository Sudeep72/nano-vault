"""Tests for nvctl v4 CLI extensions — Platform Experience & Engineering Excellence."""
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


@pytest.mark.parametrize("group", ["explore", "replay", "bench", "demo", "docgen"])
def test_new_command_groups_exist(group):
    runner = CliRunner()
    result = runner.invoke(cli, [group, "--help"])
    assert result.exit_code == 0


@pytest.mark.parametrize("cmd", ["diagnose", "env-check", "health-summary", "wizard", "threat-model"])
def test_new_top_level_commands_exist(cmd):
    runner = CliRunner()
    result = runner.invoke(cli, [cmd, "--help"])
    assert result.exit_code == 0


def test_diagnose_command(isolated_home, monkeypatch):
    class FakeClient:
        def __init__(self): pass
        def get(self, path, **kw):
            return {"success": True, "data": {"overall_healthy": True, "config": {"passed": 5, "total": 5},
                    "environment": {"python_ok": True}, "dependencies": {"all_required_installed": True},
                    "database": {"connected": True}}}
    monkeypatch.setattr("nvctl.main.NVClient", FakeClient)
    runner = CliRunner()
    result = runner.invoke(cli, ["diagnose"])
    assert result.exit_code == 0
    assert "Overall healthy: True" in result.output


def test_explore_graph_command(isolated_home, monkeypatch):
    class FakeClient:
        def __init__(self): pass
        def get(self, path, **kw):
            return {"success": True, "data": {"node_count": 15, "edge_count": 24}}
    monkeypatch.setattr("nvctl.main.NVClient", FakeClient)
    runner = CliRunner()
    result = runner.invoke(cli, ["explore", "graph", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["data"]["node_count"] == 15


def test_bench_crypto_command(isolated_home, monkeypatch):
    class FakeClient:
        def __init__(self): pass
        def post(self, path, body=None, **kw):
            return {"success": True, "data": {"duration_ms": 42.0, "results": {}}}
    monkeypatch.setattr("nvctl.main.NVClient", FakeClient)
    runner = CliRunner()
    result = runner.invoke(cli, ["bench", "crypto", "--json"])
    assert result.exit_code == 0


def test_demo_load_command(isolated_home, monkeypatch):
    class FakeClient:
        def __init__(self): pass
        def post(self, path, body=None, **kw):
            return {"success": True, "data": {"dataset_id": "abc", "records_created": {"secrets": 16}}}
    monkeypatch.setattr("nvctl.main.NVClient", FakeClient)
    runner = CliRunner()
    result = runner.invoke(cli, ["demo", "load", "--json"])
    assert result.exit_code == 0


def test_replay_create_command(isolated_home, monkeypatch):
    class FakeClient:
        def __init__(self): pass
        def post(self, path, body=None, **kw):
            return {"success": True, "data": {"session_id": "sess-1", "event_count": 10}}
    monkeypatch.setattr("nvctl.main.NVClient", FakeClient)
    runner = CliRunner()
    result = runner.invoke(cli, ["replay", "create", "--json"])
    assert result.exit_code == 0


def test_threat_model_export_prints_content(isolated_home, monkeypatch):
    class FakeClient:
        def __init__(self): pass
        def get(self, path, **kw):
            return {"raw": "# NanoVault Threat Model\n## Spoofing: spoofing_credentials"}
    monkeypatch.setattr("nvctl.main.NVClient", FakeClient)
    runner = CliRunner()
    result = runner.invoke(cli, ["threat-model"])
    assert result.exit_code == 0
    assert "Threat Model" in result.output


def test_docgen_er_prints_content(isolated_home, monkeypatch):
    class FakeClient:
        def __init__(self): pass
        def get(self, path, **kw):
            return {"raw": "erDiagram\n    secrets ||--o{ users : owns"}
    monkeypatch.setattr("nvctl.main.NVClient", FakeClient)
    runner = CliRunner()
    result = runner.invoke(cli, ["docgen", "er"])
    assert result.exit_code == 0
    assert "erDiagram" in result.output
