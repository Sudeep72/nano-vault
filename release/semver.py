"""
Semantic Versioning helper — NanoVault v3.0 release engineering.
Parses conventional commits since the last tag and computes the next version.
Real git log parsing, no external service dependency.
"""
import re
import subprocess
import sys


def get_commits_since_tag(tag: str = None) -> list[str]:
    if tag:
        rev_range = f"{tag}..HEAD"
    else:
        rev_range = "HEAD"
    result = subprocess.run(
        ["git", "log", rev_range, "--pretty=format:%s"],
        capture_output=True, text=True, cwd=__file__.rsplit("/", 2)[0],
    )
    return [l for l in result.stdout.splitlines() if l.strip()]


def bump_type(commits: list[str]) -> str:
    """Conventional Commits: feat! / BREAKING CHANGE -> major, feat -> minor, fix -> patch."""
    has_breaking = any("BREAKING CHANGE" in c or re.match(r"^\w+!:", c) for c in commits)
    has_feat = any(c.startswith("feat") for c in commits)
    has_fix = any(c.startswith("fix") for c in commits)
    if has_breaking:
        return "major"
    if has_feat:
        return "minor"
    if has_fix:
        return "patch"
    return "none"


def next_version(current: str, bump: str) -> str:
    major, minor, patch = map(int, current.split("."))
    if bump == "major":
        return f"{major + 1}.0.0"
    if bump == "minor":
        return f"{major}.{minor + 1}.0"
    if bump == "patch":
        return f"{major}.{minor}.{patch + 1}"
    return current


if __name__ == "__main__":
    current = open("release/VERSION").read().strip()
    commits = get_commits_since_tag(f"v{current}")
    bump = bump_type(commits)
    new_version = next_version(current, bump)
    print(f"Current: {current} -> Bump: {bump} -> Next: {new_version}")
    if len(sys.argv) > 1 and sys.argv[1] == "--write":
        open("release/VERSION", "w").write(new_version + "\n")
