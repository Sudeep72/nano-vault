"""Real changelog generation from conventional-commit git history."""
import subprocess
import sys
from datetime import date


def get_commits(rev_range: str) -> list[str]:
    result = subprocess.run(
        ["git", "log", rev_range, "--pretty=format:%s|%h"],
        capture_output=True, text=True,
    )
    return [l for l in result.stdout.splitlines() if l.strip()]


def categorize(commits: list[str]) -> dict[str, list[str]]:
    cats = {"feat": [], "fix": [], "docs": [], "other": []}
    for c in commits:
        msg, sha = c.rsplit("|", 1) if "|" in c else (c, "")
        for prefix in ("feat", "fix", "docs"):
            if msg.startswith(prefix):
                cats[prefix].append(f"- {msg} ({sha})")
                break
        else:
            cats["other"].append(f"- {msg} ({sha})")
    return cats


def render(version: str, cats: dict) -> str:
    lines = [f"## v{version} — {date.today().isoformat()}", ""]
    labels = {"feat": "### Features", "fix": "### Fixes", "docs": "### Documentation", "other": "### Other"}
    for key, label in labels.items():
        if cats[key]:
            lines.append(label)
            lines.extend(cats[key])
            lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    version = open("release/VERSION").read().strip()
    rev_range = sys.argv[1] if len(sys.argv) > 1 else "HEAD"
    commits = get_commits(rev_range)
    cats = categorize(commits)
    entry = render(version, cats)
    print(entry)
    with open("CHANGELOG.md", "a") as f:
        f.write("\n" + entry + "\n")
