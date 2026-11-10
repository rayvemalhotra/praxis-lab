"""Rebuild the seven result cards from the cached training runs of system.py (5 and 6 October 2026).
Nothing is retrained; the scorecard (ranges, verdicts, per-condition false-positive rates and bytes) is recomputed
with engine.py so that the published tool shows the same fields for every dataset. Reads the praxis folders only."""
import sys, os, json, shutil, glob, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import engine

# Where the praxis folders are on this machine (read only). PRAXIS_SYSTEM = the folder that holds datasets/*.json and the cached runs;
# PRAXIS_PATH_MAP = "old_prefix=new_prefix" when the settings files were written on another machine (several pairs separated by ";").
PS = os.environ.get("PRAXIS_SYSTEM", os.path.join(os.path.dirname(os.path.dirname(HERE)), "Praxis_System"))
MAP = [tuple(pair.split("=", 1)) for pair in os.environ.get("PRAXIS_PATH_MAP", "").split(";") if "=" in pair]
OUT = os.path.join(os.path.dirname(HERE), "results")


EDGE_WHY = "normal traffic gives no device-labelled examples for one of the two attacked hosts"
KEPT_LABEL = {"edge_iiotset": "Attack_type", "datasense": "label2"}
WORDING = {
    "edge_iiotset": {
        ("about",): ("IoT and IIoT testbed, packet records, 38 cleaned features. The praxis run used three class-stratified random thirds of the records as organizations. "
                     f"Tracing (H3) was not repeated on this dataset: {EDGE_WHY}."),
        ("rules", "companies"): "organizations = three class-stratified random thirds of the records",
        ("hypotheses", "H3_note"): f"not repeated on this dataset: {EDGE_WHY}",
        ("info", "role_text"): ("Used to check that the ranking of the two approaches seen on DataSense holds on different data. The organizations are class-stratified random thirds of the records. "
                                f"Tracing (H3) was not repeated: {EDGE_WHY}."),
        ("info", "host"): "the dataset has host address columns; the cleaned copy given to the tool keeps none of them"},
    "datasense": {
        ("about",): ("Industrial IoT testbed, 38 devices in the files analyzed, one record per 10 seconds per device: 59 behavior numbers "
                     "(52 network, 7 log) and the attack type. The organizations are simulated: device groups by role."),
        ("info", "what"): ("An industrial IoT testbed. The files analyzed hold 38 devices (routers, an MQTT broker, cameras, sensors, smart plugs) recorded under normal use and under attack. "
                           "Each record summarizes 10 seconds of one device as 59 numbers (52 about its network traffic, 7 about its log messages) plus the attack name."),
        ("info", "role_text"): ("The praxis claims about H1, H2 and H3 rest on this dataset alone. The three organizations are simulated: groups of the testbed's devices by role. "
                                "The train/validation/test split was audited on 23 September."),
        ("info", "host"): "device name (38 devices in the files analyzed)"},
}


def fix(p):
    for a, b in MAP:
        if p.startswith(a):
            p = b + p[len(a):]
    return p if os.path.isabs(p) else os.path.join(PS, p)


for f in sorted(glob.glob(f"{PS}/datasets/*.json")):
    cfg = json.load(open(f))
    did = cfg["id"]
    if "path" in cfg:
        cfg["path"] = fix(cfg["path"])
    if "paths" in cfg:
        cfg["paths"] = [fix(p) for p in cfg["paths"]]
    cache = f"/tmp/cache_copy/{did}"
    if not os.path.exists(cache):
        shutil.copytree(f"{PS}/cache/{did}", cache)
        for fl in glob.glob(f"{cache}/*_flower.pkl"):
            os.remove(fl)
    t = time.time()
    card = engine.run(cfg, budget=engine.PROTOCOL, log=lambda m: None, cache=cache)
    card["id"] = did
    card["study_role"] = cfg.get("study_role", "tool test")
    card["info"] = cfg.get("info", {})
    card["computed"] = "training results cached from the 5 and 6 October 2026 runs of system.py; scorecard recomputed by this tool"
    for path, text in WORDING.get(did, {}).items():          # the wording of the two praxis cards as the fact sheet states it (no number is touched)
        node = card
        for k in path[:-1]:
            node = node[k]
        node[path[-1]] = text
    if did in KEPT_LABEL:                                    # the kept attack-type column is not a removed column
        card["step2"]["removed_columns"] = [x for x in card["step2"]["removed_columns"] if x != KEPT_LABEL[did]]
    json.dump(card, open(f"{OUT}/{did}.json", "w"), indent=1, default=float)
    h1, h2 = card["hypotheses"]["H1"], card["hypotheses"]["H2"]
    print(f"{did:12s} H1 {h1['gain']*100:+.1f} [{h1['lo']*100:+.1f},{h1['hi']*100:+.1f}]  H2 {h2['gain']*100:+.1f} [{h2['lo']*100:+.1f},{h2['hi']*100:+.1f}]  H3 {card['hypotheses']['H3']}  {time.time()-t:.0f}s")
    for o, c in card["companies"].items():
        print("   ", o, c["never_seen"], "named", {r[2:5]: round(v * 100, 1) for r, v in c["named"].items()},
              "fp", {r[2:5]: round(v * 100, 2) for r, v in c["false_alarm"].items()},
              "|", card["verdicts"][o]["2_sharing"], "|", card["verdicts"][o]["3_federated"])
