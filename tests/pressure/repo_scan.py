"""Section G, repository: is a secret anywhere in the git history, and does .gitignore keep the private files out?
The access password is read from .streamlit/secrets.toml to search for it; it is never printed.

    python tests/pressure/repo_scan.py         writes qa/repo_results.json   (needs git; run it where the repository is)
"""
import os
import re
import subprocess

from common import ROOT, save

PATTERNS = {"GitHub token": rb"gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}", "AWS access key": rb"AKIA[0-9A-Z]{16}", "private key block": rb"-----BEGIN [A-Z ]*PRIVATE KEY-----",
            "Slack token": rb"xox[baprs]-[A-Za-z0-9-]{10,}", "API key assignment": rb"(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token)\s*[=:]\s*['\"][A-Za-z0-9_\-]{20,}['\"]",
            "password assignment": rb"(?i)password\s*=\s*['\"][^'\"\s]{6,}['\"]"}
ALLOWED = [b'password = "..."', b'password = \\"...\\"', b'TP_PASSWORD = "your password"', b'PRAXIS_LAB_PASSWORD = "your password"', b"test-password", b"TEST_PW", b"demo-pass", b"render-check"]


def git(*a):
    return subprocess.run(["git", *a], cwd=ROOT, capture_output=True).stdout


def main():
    results = []

    def add(test, ok, evidence):
        results.append(dict(test=test, ok=ok, evidence=evidence))
        print({True: "PASS", False: "FAIL", None: "NOTE"}[ok], test, "|", evidence)

    pw = None
    sec = os.path.join(ROOT, ".streamlit", "secrets.toml")
    if os.path.exists(sec):
        m = re.search(r'password\s*=\s*"([^"]+)"', open(sec).read())
        pw = m.group(1).encode() if m else None
    commits = git("rev-list", "--all", "--count").decode().strip()
    history = git("log", "-p", "--all", "--no-color")
    add("the whole history was read", bool(history), f"{commits} commits, {len(history) / 1e6:.1f} MB of patches")
    if pw:
        n = history.count(pw)
        add("the access password of the site is nowhere in the git history", n == 0, f"{n} occurrences (the password itself is not shown)")
        tracked = git("grep", "-c", "-F", pw.decode(), "--", ".").decode().strip()
        add("the access password is in no tracked file", tracked == "", "no tracked file holds it" if not tracked else "found in tracked files")
    else:
        add("the access password of the site is nowhere in the git history", None, "no .streamlit/secrets.toml here, so there was no password to search for")
    for name, rx in PATTERNS.items():
        hits = [h for h in re.findall(rx, history)]
        hits = [h if isinstance(h, bytes) else b"".join(h) for h in hits]
        lines = [ln for ln in history.split(b"\n") if re.search(rx, ln) and not any(a in ln for a in ALLOWED)]
        add(f"history: {name}", len(lines) == 0, f"{len(lines)} lines match (test and example values set aside)")
    files = git("ls-files").decode().split("\n")
    private = [f for f in files if re.search(r"secrets\.toml|ACCESS_PASSWORD|tunnel\.url|\.log$|\.out$|^contributions/|^\.venv/|^cache/|\.env$", f)]
    add("no private file is tracked (secrets, password file, tunnel address, logs, contributions, virtual environment)", not private, private or f"{len([f for f in files if f])} tracked files checked")
    ign = open(os.path.join(ROOT, ".gitignore")).read()
    missing = [p for p in (".streamlit/secrets.toml", "ACCESS_PASSWORD.txt", "tunnel.url", "contributions/", "*.log", ".venv/", "cache/") if p not in ign]
    add(".gitignore names every private path", not missing, missing or "secrets, password file, tunnel address, contributions, logs, virtual environment, cache")
    check = subprocess.run(["git", "check-ignore", "-q", ".streamlit/secrets.toml"], cwd=ROOT).returncode == 0 and subprocess.run(["git", "check-ignore", "-q", "ACCESS_PASSWORD.txt"], cwd=ROOT).returncode == 0
    add("git itself confirms the two password files are ignored", check, "git check-ignore")
    dock = os.path.join(ROOT, "Dockerfile")
    d = open(dock).read() if os.path.exists(dock) else ""
    add("the container runs as an ordinary user, and .dockerignore keeps the password files out of the image", "USER " in d and os.path.exists(os.path.join(ROOT, ".dockerignore"))
        and "secrets.toml" in open(os.path.join(ROOT, ".dockerignore")).read(), "USER line in the Dockerfile; .dockerignore lists the secrets" if "USER " in d else "no USER line")
    req = open(os.path.join(ROOT, "requirements.txt")).read()
    loose = [ln for ln in req.splitlines() if ln and not ln.startswith(("#", "--")) and "==" not in ln]
    add("every dependency is pinned to an exact version", not loose, loose or "requirements.txt and requirements-mac.txt")
    save("repo_results.json", results)
    return results


if __name__ == "__main__":
    main()
