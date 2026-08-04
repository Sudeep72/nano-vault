"""Config profile + credential cache for nvctl."""
import json
import os
from pathlib import Path

CONFIG_DIR = Path.home() / ".nvctl"
CONFIG_FILE = CONFIG_DIR / "config.json"
CRED_FILE = CONFIG_DIR / "credentials.json"


def ensure_config_dir():
    CONFIG_DIR.mkdir(exist_ok=True, mode=0o700)


def load_config() -> dict:
    ensure_config_dir()
    if not CONFIG_FILE.exists():
        return {"profiles": {"default": {"address": "http://localhost:8000"}}, "active_profile": "default"}
    return json.loads(CONFIG_FILE.read_text())


def save_config(config: dict):
    ensure_config_dir()
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def get_active_profile() -> dict:
    config = load_config()
    return config["profiles"][config["active_profile"]]


def set_profile(name: str, address: str):
    config = load_config()
    config["profiles"][name] = {"address": address}
    save_config(config)


def use_profile(name: str):
    config = load_config()
    if name not in config["profiles"]:
        raise ValueError(f"Profile '{name}' not found")
    config["active_profile"] = name
    save_config(config)


def load_credentials() -> dict:
    ensure_config_dir()
    if not CRED_FILE.exists():
        return {}
    return json.loads(CRED_FILE.read_text())


def save_credentials(profile: str, token: str, refresh_token: str = ""):
    ensure_config_dir()
    creds = load_credentials()
    creds[profile] = {"access_token": token, "refresh_token": refresh_token}
    CRED_FILE.write_text(json.dumps(creds, indent=2))
    os.chmod(CRED_FILE, 0o600)


def clear_credentials(profile: str):
    creds = load_credentials()
    creds.pop(profile, None)
    CRED_FILE.write_text(json.dumps(creds, indent=2))


def get_token(profile: str) -> str:
    creds = load_credentials()
    return creds.get(profile, {}).get("access_token", "")
