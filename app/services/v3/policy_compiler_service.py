from __future__ import annotations
import json, uuid, fnmatch
from datetime import datetime, timezone
import yaml
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException
from app.models.models import PolicyFile, PolicyFileVersion, PolicyFileFormat, Policy

def _now(): return datetime.now(timezone.utc)
VALID_ACTIONS = {"create","read","update","delete","list"}

def _parse_hcl(content):
    perms = []; lines = content.strip().splitlines(); i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith("path "):
            parts = line.split('"')
            if len(parts) >= 2:
                path = parts[1]; caps = []; deny = False; i += 1
                while i < len(lines) and "}" not in lines[i]:
                    inner = lines[i].strip()
                    if inner.startswith("capabilities"):
                        raw = inner.split("[")[1].split("]")[0]
                        caps = [c.strip().strip('"') for c in raw.split(",")]
                    elif inner.startswith("deny") and "true" in inner: deny = True
                    i += 1
                perms.append({"path": path, "actions": caps, "deny": deny})
        i += 1
    return perms

def _parse(content, fmt):
    if fmt == PolicyFileFormat.JSON:
        d = json.loads(content)
        return d if isinstance(d, list) else d.get("permissions", d.get("rules", []))
    elif fmt == PolicyFileFormat.YAML:
        d = yaml.safe_load(content)
        return d if isinstance(d, list) else d.get("permissions", d.get("rules", []))
    elif fmt == PolicyFileFormat.HCL:
        return _parse_hcl(content)
    raise HTTPException(400, f"Unsupported format: {fmt}")

def _validate(perms):
    errors = []
    for i, r in enumerate(perms):
        if "path" not in r: errors.append(f"Rule {i}: missing 'path'")
        if "actions" not in r: errors.append(f"Rule {i}: missing 'actions'")
        else:
            bad = [a for a in r["actions"] if a not in VALID_ACTIONS]
            if bad: errors.append(f"Rule {i}: invalid actions {bad}")
    return errors

def _diff(old, new):
    om = {r.get("path",""): r for r in old}; nm = {r.get("path",""): r for r in new}
    added = [r for p,r in nm.items() if p not in om]
    removed = [r for p,r in om.items() if p not in nm]
    changed = [{"path": p, "old": om[p], "new": nm[p]} for p in om if p in nm and om[p] != nm[p]]
    return {"added": added, "removed": removed, "changed": changed, "total_changes": len(added)+len(removed)+len(changed)}

class PolicyCompilerService:
    @staticmethod
    async def upload(db, name, content, fmt, description=None, created_by=None, apply=False):
        try: perms = _parse(content, fmt)
        except Exception as e: raise HTTPException(422, f"Parse error: {e}")
        errors = _validate(perms); is_valid = len(errors) == 0
        existing = (await db.execute(select(PolicyFile).where(PolicyFile.name==name))).scalar_one_or_none()
        if existing:
            vnum = existing.current_version + 1
            old_ver = (await db.execute(select(PolicyFileVersion).where(PolicyFileVersion.policy_file_id==existing.id, PolicyFileVersion.is_current==True))).scalar_one_or_none()
            if old_ver: old_ver.is_current = False
            existing.current_version = vnum; pf = existing
        else:
            vnum = 1
            pf = PolicyFile(name=name, description=description, format=fmt, current_version=1, created_by=created_by)
            db.add(pf); await db.flush()
        ver = PolicyFileVersion(policy_file_id=pf.id, version_number=vnum, content=content, parsed_permissions=perms,
            is_valid=is_valid, validation_errors=errors if errors else None, is_current=True,
            created_by=created_by, applied_at=_now() if (apply and is_valid) else None)
        db.add(ver); await db.flush()
        if apply and is_valid: await PolicyCompilerService._apply_to_engine(db, name, perms, created_by)
        return {"policy_file": name, "version": vnum, "format": fmt.value, "is_valid": is_valid,
                "validation_errors": errors, "permissions_parsed": len(perms), "applied": apply and is_valid}

    @staticmethod
    async def _apply_to_engine(db, name, perms, created_by):
        existing = (await db.execute(select(Policy).where(Policy.name==f"pac:{name}"))).scalar_one_or_none()
        if existing:
            existing.permissions = perms; existing.updated_at = _now()
        else:
            db.add(Policy(name=f"pac:{name}", description=f"Policy as Code — {name}", permissions=perms, is_builtin=False))
        await db.flush()

    @staticmethod
    async def validate(content, fmt):
        try: perms = _parse(content, fmt)
        except Exception as e: return {"valid": False, "errors": [str(e)], "permissions": []}
        errors = _validate(perms)
        return {"valid": len(errors)==0, "errors": errors, "permissions_parsed": len(perms), "permissions": perms}

    @staticmethod
    async def simulate(db, policy_name, secret_key, action):
        pf = (await db.execute(select(PolicyFile).where(PolicyFile.name==policy_name))).scalar_one_or_none()
        if not pf: raise HTTPException(404, f"'{policy_name}' not found")
        ver = (await db.execute(select(PolicyFileVersion).where(PolicyFileVersion.policy_file_id==pf.id, PolicyFileVersion.is_current==True))).scalar_one_or_none()
        if not ver: raise HTTPException(404, "No current version")
        perms = ver.parsed_permissions or []; matched = []; decision = False
        for rule in perms:
            path = rule.get("path",""); actions = rule.get("actions",[]); deny = rule.get("deny", False)
            if fnmatch.fnmatch(secret_key, path) and action in actions:
                matched.append({**rule, "matched": True})
                decision = False if deny else True
        return {"policy": policy_name, "secret_key": secret_key, "action": action, "allowed": decision,
                "matched_rules": matched, "total_rules_evaluated": len(perms)}

    @staticmethod
    async def diff(db, policy_name, va, vb):
        pf = (await db.execute(select(PolicyFile).where(PolicyFile.name==policy_name))).scalar_one_or_none()
        if not pf: raise HTTPException(404, f"'{policy_name}' not found")
        a = (await db.execute(select(PolicyFileVersion).where(PolicyFileVersion.policy_file_id==pf.id, PolicyFileVersion.version_number==va))).scalar_one_or_none()
        b = (await db.execute(select(PolicyFileVersion).where(PolicyFileVersion.policy_file_id==pf.id, PolicyFileVersion.version_number==vb))).scalar_one_or_none()
        if not a or not b: raise HTTPException(404, "Version(s) not found")
        d = _diff(a.parsed_permissions or [], b.parsed_permissions or [])
        return {"policy": policy_name, "version_a": va, "version_b": vb, **d}

    @staticmethod
    async def rollback(db, policy_name, target_version):
        pf = (await db.execute(select(PolicyFile).where(PolicyFile.name==policy_name))).scalar_one_or_none()
        if not pf: raise HTTPException(404, f"'{policy_name}' not found")
        target = (await db.execute(select(PolicyFileVersion).where(PolicyFileVersion.policy_file_id==pf.id, PolicyFileVersion.version_number==target_version))).scalar_one_or_none()
        if not target: raise HTTPException(404, f"Version {target_version} not found")
        current = (await db.execute(select(PolicyFileVersion).where(PolicyFileVersion.policy_file_id==pf.id, PolicyFileVersion.is_current==True))).scalar_one_or_none()
        if current: current.is_current = False
        new_v = pf.current_version + 1; pf.current_version = new_v
        db.add(PolicyFileVersion(policy_file_id=pf.id, version_number=new_v, content=target.content,
            parsed_permissions=target.parsed_permissions, is_valid=target.is_valid, is_current=True, applied_at=_now()))
        await db.flush()
        if target.is_valid: await PolicyCompilerService._apply_to_engine(db, policy_name, target.parsed_permissions or [], None)
        return {"policy": policy_name, "rolled_back_to": target_version, "new_version": new_v, "applied": target.is_valid}

    @staticmethod
    async def list_files(db):
        files = (await db.execute(select(PolicyFile).order_by(PolicyFile.name))).scalars().all()
        return [{"id": str(f.id), "name": f.name, "format": f.format.value, "current_version": f.current_version,
                 "is_active": f.is_active, "description": f.description, "created_at": f.created_at.isoformat()} for f in files]

    @staticmethod
    async def get_versions(db, policy_name):
        pf = (await db.execute(select(PolicyFile).where(PolicyFile.name==policy_name))).scalar_one_or_none()
        if not pf: raise HTTPException(404, f"'{policy_name}' not found")
        versions = (await db.execute(select(PolicyFileVersion).where(PolicyFileVersion.policy_file_id==pf.id).order_by(PolicyFileVersion.version_number.desc()))).scalars().all()
        return [{"version": v.version_number, "is_current": v.is_current, "is_valid": v.is_valid,
                 "validation_errors": v.validation_errors, "permissions_count": len(v.parsed_permissions or []),
                 "applied_at": v.applied_at.isoformat() if v.applied_at else None, "created_at": v.created_at.isoformat()} for v in versions]

policy_compiler_service = PolicyCompilerService()
