"""Check every MITRE ATT&CK identifier and name used in threatprint_agent.py against MITRE's published STIX data.

    python tools/verify_attack_ids.py ENTERPRISE.json ICS.json

Get the two files from https://github.com/mitre-attack/attack-stix-data (enterprise-attack/enterprise-attack.json and
ics-attack/ics-attack.json). Exit code 1 if an identifier is missing, revoked, deprecated or named differently."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import threatprint_agent as agent


def load(path):
    d = json.load(open(path))
    col = [o for o in d["objects"] if o["type"] == "x-mitre-collection"]
    tech, parent = {}, {}
    for o in d["objects"]:
        if o["type"] != "attack-pattern":
            continue
        ext = [e for e in o.get("external_references", []) if e.get("source_name") == "mitre-attack"]
        if ext:
            tech[ext[0]["external_id"]] = (o["name"], bool(o.get("revoked")) or bool(o.get("x_mitre_deprecated")))
    return tech, (col[0].get("x_mitre_version") if col else "?")


ent, ev = load(sys.argv[1])
ics, iv = load(sys.argv[2])
print(f"Enterprise ATT&CK version {ev}; ICS ATT&CK version {iv}")
bad = 0
for tid, (matrix, name) in agent.T.items():
    src = ent if matrix == "Enterprise" else ics
    got = src.get(tid)
    full = None
    if got:
        full = got[0]
        if "." in tid and src.get(tid.split(".")[0]):
            full = f"{src[tid.split('.')[0]][0]}: {got[0]}"
    ok = bool(got) and not got[1] and full == name
    bad += 0 if ok else 1
    print(f"{'ok ' if ok else 'BAD'} {tid:10s} {matrix:10s} ours: {name!r}   MITRE: {full!r}{'  (revoked or deprecated)' if got and got[1] else ''}")
print("all identifiers match" if not bad else f"{bad} identifiers do not match")
sys.exit(1 if bad else 0)
