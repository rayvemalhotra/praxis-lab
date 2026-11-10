"""Section G, dependencies: known advisories for the packages of an environment (pip-audit, the PyPA advisory database).

    python tests/pressure/audit.py                      the environment that runs this script
    python tests/pressure/audit.py FROZEN.txt NAME      a 'pip freeze' list of another machine (for example the Mac that serves the site)

Writes a short summary to qa/audit_results.json (one entry per environment). Needs pip-audit (test-only); skipped without it.
"""
import json
import os
import subprocess
import sys
import tempfile

from common import load, save


def main():
    try:
        import pip_audit  # noqa: F401
    except Exception:
        print("pip-audit is not installed here; not run")
        return None
    import platform
    name = sys.argv[2] if len(sys.argv) > 2 else f"the environment that ran the suite ({platform.system()} {platform.machine()}; it also holds test-only packages)"
    out = os.path.join(tempfile.gettempdir(), "tp_audit.json")
    if len(sys.argv) > 1:
        req = os.path.join(tempfile.gettempdir(), "tp_audit_req.txt")
        lines = [ln for ln in open(sys.argv[1]).read().splitlines() if ln and "==" in ln and not ln.startswith("torch==")]
        open(req, "w").write("\n".join(lines) + "\n")
        cmd = [sys.executable, "-m", "pip_audit", "-r", req, "--no-deps", "--disable-pip", "--progress-spinner", "off", "-f", "json", "-o", out]
    else:
        cmd = [sys.executable, "-m", "pip_audit", "--local", "--progress-spinner", "off", "-f", "json", "-o", out]
    subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    d = json.load(open(out))
    pk = []
    for p in d["dependencies"]:
        ids = sorted({v["id"] for v in p.get("vulns", [])})
        if ids:
            fixes = sorted({f for v in p["vulns"] for f in v.get("fix_versions", [])}, key=lambda x: [int(t) if t.isdigit() else 0 for t in x.split(".")])
            pk.append(dict(package=p["name"], version=p["version"], advisories=len(ids), clean_from=fixes[-1] if fixes else "no fixed version listed",
                           ids=[v for v in ids if v.startswith(("CVE", "PYSEC"))][:6]))
    res = load("audit_results.json", {}) or {}
    res[name] = dict(packages_checked=len(d["dependencies"]), packages_with_advisories=pk, not_checked=["torch (the CPU build is not on PyPI under that version name)"])
    save("audit_results.json", res)
    print(name, json.dumps(res[name])[:600])
    return res


if __name__ == "__main__":
    main()
