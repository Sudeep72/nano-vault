"""Tests for nvctl CLI — verifies command structure and config module (no live server needed)."""
import json
import tempfile
from pathlib import Path
from click.testing import CliRunner
import pytest

import sys
sys.path.insert(0, "/home/claude/nano_vault/cli")

from nvctl.main import cli
from nvctl import config as cfg_module


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setattr(cfg_module, "CONFIG_DIR", tmp_path / ".nvctl")
    monkeypatch.setattr(cfg_module, "CONFIG_FILE", tmp_path / ".nvctl" / "config.json")
    monkeypatch.setattr(cfg_module, "CRED_FILE", tmp_path / ".nvctl" / "credentials.json")
    return tmp_path


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "nvctl" in result.output


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "3.0.0" in result.output


@pytest.mark.parametrize("group", ["auth", "secret", "transit", "pki", "namespace", "policy", "token", "lease", "engine", "storage", "vault", "profile"])
def test_all_command_groups_exist(group):
    runner = CliRunner()
    result = runner.invoke(cli, [group, "--help"])
    assert result.exit_code == 0


def test_profile_create_and_use(isolated_home):
    cfg_module.set_profile("test-profile", "http://test:9000")
    config = cfg_module.load_config()
    assert config["profiles"]["test-profile"]["address"] == "http://test:9000"

    cfg_module.use_profile("test-profile")
    config = cfg_module.load_config()
    assert config["active_profile"] == "test-profile"


def test_profile_use_nonexistent_raises(isolated_home):
    with pytest.raises(ValueError):
        cfg_module.use_profile("does-not-exist")


def test_credentials_save_load_clear(isolated_home):
    cfg_module.save_credentials("default", "tok123", "refresh456")
    token = cfg_module.get_token("default")
    assert token == "tok123"

    cfg_module.clear_credentials("default")
    token = cfg_module.get_token("default")
    assert token == ""


def test_policy_validate_command_with_file(isolated_home, tmp_path, monkeypatch):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("permissions:\n  - path: \"aws/*\"\n    actions: [\"read\"]\n")

    class FakeClient:
        def __init__(self): pass
        def post(self, path, body=None, **kw):
            return {"success": True, "data": {"valid": True, "errors": []}}

    monkeypatch.setattr("nvctl.main.NVClient", FakeClient)
    runner = CliRunner()
    result = runner.invoke(cli, ["policy", "validate", str(policy_file)])
    assert result.exit_code == 0
    assert "Valid: True" in result.output


def test_transit_encrypt_command(isolated_home, monkeypatch):
    class FakeClient:
        def __init__(self): pass
        def post(self, path, body=None, **kw):
            return {"success": True, "data": {"ciphertext": "vault:v1:xxxx", "key_version": 1}}

    monkeypatch.setattr("nvctl.main.NVClient", FakeClient)
    runner = CliRunner()
    result = runner.invoke(cli, ["transit", "encrypt", "mykey", "hello", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["data"]["ciphertext"] == "vault:v1:xxxx"


def test_secret_create_command(isolated_home, monkeypatch):
    class FakeClient:
        def __init__(self): pass
        def post(self, path, body=None, **kw):
            assert body["key"] == "mykey"
            return {"success": True, "data": {"id": "abc-123", "key": "mykey"}}

    monkeypatch.setattr("nvctl.main.NVClient", FakeClient)
    runner = CliRunner()
    result = runner.invoke(cli, ["secret", "create", "mykey", "myvalue", "--json"])
    assert result.exit_code == 0


def test_vault_status_command(isolated_home, monkeypatch):
    class FakeClient:
        def __init__(self): pass
        def get(self, path, **kw):
            return {"success": True, "data": {"sealed": True, "initialized": False}}

    monkeypatch.setattr("nvctl.main.NVClient", FakeClient)
    runner = CliRunner()
    result = runner.invoke(cli, ["vault", "status", "--json"])
    assert result.exit_code == 0
