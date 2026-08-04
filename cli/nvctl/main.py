#!/usr/bin/env python3
"""
nvctl — NanoVault Enterprise CLI
Cross-platform (Linux/macOS/Windows) operational interface for NanoVault v3.0.
"""
import base64
import json as json_lib
import sys
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .client import NVClient
from .config import load_config, save_config, set_profile, use_profile, save_credentials, clear_credentials

console = Console()


def out(data, as_json=False, title=None):
    if as_json:
        click.echo(json_lib.dumps(data, indent=2))
        return
    if title:
        console.print(Panel.fit(title, style="bold cyan"))
    if isinstance(data, dict) and "data" in data:
        payload = data["data"]
    else:
        payload = data
    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        table = Table(show_header=True, header_style="bold magenta")
        for key in payload[0].keys():
            table.add_column(key)
        for row in payload:
            table.add_row(*[str(v) for v in row.values()])
        console.print(table)
    else:
        console.print_json(data=payload if isinstance(payload, (dict, list)) else {"result": payload})


json_opt = click.option("--json", "as_json", is_flag=True, help="Output raw JSON")


@click.group()
@click.version_option(version="3.0.0", prog_name="nvctl")
def cli():
    """nvctl — NanoVault Enterprise CLI. The primary operational interface for NanoVault v3.0."""
    pass


# ── Config / Profiles ─────────────────────────────────────────────────────────

@cli.group()
def profile():
    """Manage configuration profiles."""
    pass


@profile.command("create")
@click.argument("name")
@click.option("--address", default="http://localhost:8000", help="NanoVault server address")
def profile_create(name, address):
    set_profile(name, address)
    console.print(f"[green]Profile '{name}' created -> {address}[/green]")


@profile.command("use")
@click.argument("name")
def profile_use(name):
    use_profile(name)
    console.print(f"[green]Active profile: {name}[/green]")


@profile.command("list")
def profile_list():
    config = load_config()
    for name, p in config["profiles"].items():
        marker = " (active)" if name == config["active_profile"] else ""
        console.print(f"{name}{marker}: {p['address']}")


# ── Auth ──────────────────────────────────────────────────────────────────────

@cli.group()
def auth():
    """Authentication: login, logout, profile."""
    pass


@auth.command("login")
@click.option("--username", prompt=True)
@click.option("--password", prompt=True, hide_input=True)
@json_opt
def auth_login(username, password, as_json):
    client = NVClient()
    resp = client.post("/api/v1/auth/login", {"username": username, "password": password}, auth=False)
    if resp.get("success"):
        token = resp["data"]["access_token"]
        refresh = resp["data"]["refresh_token"]
        save_credentials(client.profile_name, token, refresh)
        console.print("[green]Login successful. Token cached.[/green]")
    else:
        console.print(f"[red]Login failed: {resp.get('detail', resp)}[/red]")
    out(resp, as_json)


@auth.command("logout")
def auth_logout():
    client = NVClient()
    clear_credentials(client.profile_name)
    console.print("[green]Logged out. Local credential cache cleared.[/green]")


@auth.command("whoami")
@json_opt
def auth_whoami(as_json):
    client = NVClient()
    resp = client.get("/api/v1/auth/me")
    out(resp, as_json, "Current User")


# ── Secrets ───────────────────────────────────────────────────────────────────

@cli.group()
def secret():
    """KV Secrets: create, read, update, delete, search, rotate, rollback."""
    pass


@secret.command("create")
@click.argument("key")
@click.argument("value")
@click.option("--category")
@click.option("--tags", multiple=True)
@json_opt
def secret_create(key, value, category, tags, as_json):
    client = NVClient()
    body = {"key": key, "value": value}
    if category: body["category"] = category
    if tags: body["tags"] = list(tags)
    resp = client.post("/api/v1/secrets", body)
    out(resp, as_json, f"Secret Created: {key}")


@secret.command("read")
@click.argument("secret_id")
@json_opt
def secret_read(secret_id, as_json):
    client = NVClient()
    resp = client.get(f"/api/v1/secrets/{secret_id}")
    out(resp, as_json)


@secret.command("update")
@click.argument("secret_id")
@click.option("--value")
@json_opt
def secret_update(secret_id, value, as_json):
    client = NVClient()
    resp = client.patch(f"/api/v1/secrets/{secret_id}", {"value": value})
    out(resp, as_json)


@secret.command("delete")
@click.argument("secret_id")
def secret_delete(secret_id):
    client = NVClient()
    resp = client.delete(f"/api/v1/secrets/{secret_id}")
    console.print(f"[yellow]{resp.get('message', resp)}[/yellow]")


@secret.command("search")
@click.option("--query")
@click.option("--category")
@json_opt
def secret_search(query, category, as_json):
    client = NVClient()
    body = {}
    if query: body["query"] = query
    if category: body["category"] = category
    resp = client.post("/api/v1/secrets/search", body)
    out(resp, as_json, "Search Results")


@secret.command("rotate")
@click.argument("secret_id")
@click.argument("new_value")
def secret_rotate(secret_id, new_value):
    client = NVClient()
    resp = client.post(f"/api/v2/kv/{secret_id}/rotate", {"new_value": new_value})
    console.print(f"[green]{resp.get('message', resp)}[/green]")


@secret.command("rollback")
@click.argument("secret_id")
@click.argument("version", type=int)
def secret_rollback(secret_id, version):
    client = NVClient()
    resp = client.post(f"/api/v2/kv/{secret_id}/rollback", {"version_number": version})
    console.print(f"[green]{resp.get('message', resp)}[/green]")


# ── Transit ───────────────────────────────────────────────────────────────────

@cli.group()
def transit():
    """Transit Engine: encrypt, decrypt, sign, verify, rotate."""
    pass


@transit.command("encrypt")
@click.argument("key_name")
@click.argument("plaintext")
@json_opt
def transit_encrypt(key_name, plaintext, as_json):
    client = NVClient()
    b64 = base64.b64encode(plaintext.encode()).decode()
    resp = client.post(f"/api/v3/transit/encrypt/{key_name}", {"plaintext": b64})
    out(resp, as_json)


@transit.command("decrypt")
@click.argument("key_name")
@click.argument("ciphertext")
@json_opt
def transit_decrypt(key_name, ciphertext, as_json):
    client = NVClient()
    resp = client.post(f"/api/v3/transit/decrypt/{key_name}", {"ciphertext": ciphertext})
    if resp.get("success"):
        pt = base64.b64decode(resp["data"]["plaintext"]).decode()
        console.print(f"[green]Plaintext: {pt}[/green]")
    out(resp, as_json)


@transit.command("sign")
@click.argument("key_name")
@click.argument("data")
@json_opt
def transit_sign(key_name, data, as_json):
    client = NVClient()
    b64 = base64.b64encode(data.encode()).decode()
    resp = client.post(f"/api/v3/transit/sign/{key_name}", {"input": b64})
    out(resp, as_json)


@transit.command("verify")
@click.argument("key_name")
@click.argument("data")
@click.argument("signature")
@json_opt
def transit_verify(key_name, data, signature, as_json):
    client = NVClient()
    b64 = base64.b64encode(data.encode()).decode()
    resp = client.post(f"/api/v3/transit/verify/{key_name}", {"input": b64, "signature": signature})
    out(resp, as_json)


@transit.command("rotate")
@click.argument("key_name")
def transit_rotate(key_name):
    client = NVClient()
    resp = client.post(f"/api/v3/transit/keys/{key_name}/rotate")
    console.print(f"[green]{resp.get('message', resp)}[/green]")


# ── PKI ───────────────────────────────────────────────────────────────────────

@cli.group()
def pki():
    """PKI Engine: issue, renew, revoke certificates."""
    pass


@pki.command("issue")
@click.argument("ca_id")
@click.argument("common_name")
@click.option("--type", "cert_type", default="server")
@click.option("--ttl-days", default=365)
@json_opt
def pki_issue(ca_id, common_name, cert_type, ttl_days, as_json):
    client = NVClient()
    resp = client.post("/api/v3/pki/issue", {"ca_id": ca_id, "common_name": common_name, "cert_type": cert_type, "ttl_days": ttl_days})
    out(resp, as_json)


@pki.command("revoke")
@click.argument("cert_id")
@click.option("--reason", default="unspecified")
def pki_revoke(cert_id, reason):
    client = NVClient()
    resp = client.post(f"/api/v3/pki/certificates/{cert_id}/revoke", {"reason": reason})
    console.print(f"[yellow]{resp.get('message', resp)}[/yellow]")


@pki.command("renew")
@click.argument("cert_id")
@click.option("--ttl-days", default=365)
@json_opt
def pki_renew(cert_id, ttl_days, as_json):
    client = NVClient()
    resp = client.post(f"/api/v3/pki/certificates/{cert_id}/renew", {"ttl_days": ttl_days})
    out(resp, as_json)


# ── Namespaces ────────────────────────────────────────────────────────────────

@cli.group()
def namespace():
    """Namespace management: create, switch, delete."""
    pass


@namespace.command("create")
@click.argument("org_id")
@click.argument("name")
@click.argument("path")
def namespace_create(org_id, name, path):
    client = NVClient()
    resp = client.post("/api/v2/namespaces", {"org_id": org_id, "name": name, "path": path})
    console.print(f"[green]{resp.get('message', resp)}[/green]")


@namespace.command("switch")
@click.argument("path")
def namespace_switch(path):
    client = NVClient()
    resp = client.post("/api/v2/namespaces/switch", {"path": path})
    console.print(f"[green]{resp.get('message', resp)}[/green]")


@namespace.command("delete")
@click.argument("ns_id")
def namespace_delete(ns_id):
    client = NVClient()
    resp = client.delete(f"/api/v2/namespaces/{ns_id}")
    console.print(f"[yellow]{resp.get('message', resp)}[/yellow]")


# ── Policies ──────────────────────────────────────────────────────────────────

@cli.group()
def policy():
    """Policy as Code: create, validate, simulate, import, export."""
    pass


@policy.command("import")
@click.argument("name")
@click.argument("file", type=click.Path(exists=True))
@click.option("--format", "fmt", default="yaml", type=click.Choice(["yaml", "json", "hcl"]))
@click.option("--apply", is_flag=True)
def policy_import(name, file, fmt, apply):
    client = NVClient()
    content = open(file).read()
    resp = client.post("/api/v3/policy-as-code/upload", {"name": name, "content": content, "format": fmt, "apply": apply})
    console.print(f"[green]{resp.get('message', resp)}[/green]")


@policy.command("export")
@click.argument("name")
@click.option("--output", "-o", type=click.Path())
def policy_export(name, output):
    client = NVClient()
    resp = client.get(f"/api/v3/policy-as-code/{name}/versions")
    content = json_lib.dumps(resp.get("data", []), indent=2)
    if output:
        open(output, "w").write(content)
        console.print(f"[green]Exported to {output}[/green]")
    else:
        console.print(content)


@policy.command("validate")
@click.argument("file", type=click.Path(exists=True))
@click.option("--format", "fmt", default="yaml", type=click.Choice(["yaml", "json", "hcl"]))
def policy_validate(file, fmt):
    client = NVClient()
    content = open(file).read()
    resp = client.post("/api/v3/policy-as-code/validate", {"content": content, "format": fmt})
    valid = resp.get("data", {}).get("valid")
    color = "green" if valid else "red"
    console.print(f"[{color}]Valid: {valid}[/{color}]")
    if not valid:
        for e in resp["data"].get("errors", []):
            console.print(f"  - {e}")


@policy.command("simulate")
@click.argument("policy_name")
@click.argument("secret_key")
@click.argument("action")
def policy_simulate(policy_name, secret_key, action):
    client = NVClient()
    resp = client.post("/api/v3/policy-as-code/simulate", {"policy_name": policy_name, "secret_key": secret_key, "action": action})
    allowed = resp.get("data", {}).get("allowed")
    color = "green" if allowed else "red"
    console.print(f"[{color}]Allowed: {allowed}[/{color}]")


# ── Tokens ────────────────────────────────────────────────────────────────────

@cli.group()
def token():
    """Vault Token Engine: create, renew, revoke, lookup."""
    pass


@token.command("create")
@click.option("--ttl", default=3600)
@click.option("--type", "token_type", default="service")
@json_opt
def token_create(ttl, token_type, as_json):
    client = NVClient()
    resp = client.post("/api/v2/tokens/create", {"ttl_seconds": ttl, "token_type": token_type})
    out(resp, as_json)


@token.command("renew")
@click.argument("raw_token")
def token_renew(raw_token):
    client = NVClient()
    resp = client.post("/api/v2/tokens/renew", {"token": raw_token})
    console.print(f"[green]{resp.get('message', resp)}[/green]")


@token.command("revoke")
@click.argument("raw_token")
def token_revoke(raw_token):
    client = NVClient()
    resp = client.post("/api/v2/tokens/revoke", {"token": raw_token})
    console.print(f"[yellow]{resp.get('message', resp)}[/yellow]")


@token.command("lookup")
@click.argument("raw_token")
@json_opt
def token_lookup(raw_token, as_json):
    client = NVClient()
    resp = client.post("/api/v2/tokens/lookup", {"token": raw_token})
    out(resp, as_json)


# ── Leases ────────────────────────────────────────────────────────────────────

@cli.group()
def lease():
    """Lease Engine: lookup, renew, revoke."""
    pass


@lease.command("lookup")
@click.argument("lease_id")
@json_opt
def lease_lookup(lease_id, as_json):
    client = NVClient()
    resp = client.post("/api/v2/dynamic/leases/lookup", {"lease_id": lease_id})
    out(resp, as_json)


@lease.command("renew")
@click.argument("lease_id")
@click.option("--increment", default=3600)
def lease_renew(lease_id, increment):
    client = NVClient()
    resp = client.post("/api/v2/dynamic/leases/renew", {"lease_id": lease_id, "increment_seconds": increment})
    console.print(f"[green]{resp.get('message', resp)}[/green]")


@lease.command("revoke")
@click.argument("lease_id")
def lease_revoke(lease_id):
    client = NVClient()
    resp = client.post("/api/v2/dynamic/leases/revoke", {"lease_id": lease_id})
    console.print(f"[yellow]{resp.get('message', resp)}[/yellow]")


# ── Engines ───────────────────────────────────────────────────────────────────

@cli.group()
def engine():
    """Engine management: list, enable, disable, mount, unmount, reload."""
    pass


@engine.command("list")
@json_opt
def engine_list(as_json):
    client = NVClient()
    resp = client.get("/api/v2/engines")
    out(resp, as_json, "Registered Engines")


@engine.command("enable")
@click.argument("name")
def engine_enable(name):
    client = NVClient()
    resp = client.post(f"/api/v2/engines/{name}/enable")
    console.print(f"[green]{resp.get('message', resp)}[/green]")


@engine.command("disable")
@click.argument("name")
def engine_disable(name):
    client = NVClient()
    resp = client.post(f"/api/v2/engines/{name}/disable")
    console.print(f"[yellow]{resp.get('message', resp)}[/yellow]")


@engine.command("mount")
@click.argument("name")
@click.option("--path")
def engine_mount(name, path):
    client = NVClient()
    body = {"mount_path": path} if path else {}
    resp = client.post(f"/api/v2/engines/{name}/mount", body)
    console.print(f"[green]{resp.get('message', resp)}[/green]")


@engine.command("unmount")
@click.argument("name")
def engine_unmount(name):
    client = NVClient()
    resp = client.post(f"/api/v2/engines/{name}/unmount")
    console.print(f"[yellow]{resp.get('message', resp)}[/yellow]")


@engine.command("reload")
@click.argument("name")
def engine_reload(name):
    client = NVClient()
    resp = client.post(f"/api/v2/engines/{name}/reload")
    console.print(f"[green]{resp.get('message', resp)}[/green]")


# ── Storage / Backup ──────────────────────────────────────────────────────────

@cli.group()
def storage():
    """Storage: backup, restore."""
    pass


@storage.command("backup")
@click.option("--type", "backup_type", default="full")
@json_opt
def storage_backup(backup_type, as_json):
    client = NVClient()
    resp = client.post("/api/v3/backup", {"backup_type": backup_type})
    out(resp, as_json, "Backup Created")


@storage.command("restore")
@click.argument("backup_id")
def storage_restore(backup_id):
    client = NVClient()
    resp = client.post(f"/api/v3/backup/{backup_id}/restore")
    console.print(f"[green]{resp.get('message', resp)}[/green]")


@storage.command("list-backups")
@json_opt
def storage_list_backups(as_json):
    client = NVClient()
    resp = client.get("/api/v3/backup")
    out(resp, as_json, "Backups")


# ── Vault Management ──────────────────────────────────────────────────────────

@cli.group()
def vault():
    """Vault management: seal, unseal, status, health."""
    pass

@vault.command("init")
@click.option("--shares", default=5, show_default=True)
@click.option("--threshold", default=3, show_default=True)
@json_opt
def vault_init(shares, threshold, as_json):
    """Initialize vault with Shamir key shares."""
    client = NVClient()
    resp = client.post(
        "/api/v3/seal/initialize",
        {
            "total_shares": shares,
            "threshold": threshold,
        },
    )
    out(resp, as_json, "Vault Initialized")

@vault.command("status")
@json_opt
def vault_status(as_json):
    client = NVClient()
    resp = client.get("/api/v3/seal/status", auth=False)
    out(resp, as_json, "Vault Seal Status")


@vault.command("seal")
def vault_seal():
    client = NVClient()
    resp = client.post("/api/v3/seal/seal")
    console.print(f"[yellow]{resp.get('message', resp)}[/yellow]")


@vault.command("unseal")
@click.argument("share")
def vault_unseal(share):
    client = NVClient()
    resp = client.post("/api/v3/seal/unseal", {"share": share}, auth=False)
    console.print(f"[green]{resp.get('message', resp)}[/green]")


@vault.command("health")
@json_opt
def vault_health(as_json):
    client = NVClient()
    resp = client.get("/health", auth=False)
    out(resp, as_json, "Vault Health")


# ── Shell completion ──────────────────────────────────────────────────────────

@cli.command("completion")
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]))
def completion(shell):
    """Print shell completion script. Usage: eval "$(nvctl completion bash)" """
    click.echo(f"# Add to your shell profile:\n# eval \"$(_NVCTL_COMPLETE={shell}_source nvctl)\"")


if __name__ == "__main__":
    cli()

