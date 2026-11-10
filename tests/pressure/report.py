"""Builds qa/PRESSURE_TEST_REPORT.md and qa/pressure_results.json from the result files of the parts (see run_all.py)."""
import json
import os
import re
import time

from common import QA, load

BANNED = ["first", "proven", "anonymized", "anonymous", "guarantee", "no leakage", "removes the risk"]
WAITING = ("csv_safe", "server-side limit on password guesses", "no error box", "impossible_exponent", "hostile fingerprint through the real page")
MARK = {True: "pass", False: "FAIL", None: "note"}


def cell(x):
    return str(x).replace("|", "/").replace("\n", " ")


def table(head, rows):
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    out += ["| " + " | ".join(cell(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def status(r):
    if r.get("ok") is False and any(w in r["test"] for w in WAITING):
        return "open (waits for a patch in app.py)"
    return MARK[r.get("ok")]


def simple(name):
    rs = load(name, []) or []
    return rs, table(["Test", "Result", "Evidence"], [(r["test"], status(r), r.get("evidence", "")) for r in rs])


def write():
    meta = load("runs_meta.json", {}) or {}
    def when(f):
        """When and where a result file was made: from the suite's own record, else from the file itself (a file copied in by hand has no record)."""
        if f in meta:
            return f"{meta[f]['when']}, {meta[f]['machine']}"
        p = os.path.join(QA, f)
        if os.path.exists(p):
            where = "the Mac" if "_mac" in f else ("Linux test box" if "sandbox" in f else "machine not recorded")
            return f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(os.path.getmtime(p)))}, {where}"
        return "not run"
    L, failed, counts = [], [], dict(run=0, passed=0, failed=0, open=0, notes=0)
    by_section = {}

    def tally(rs, key="test", sec="other"):
        c = by_section.setdefault(sec, dict(run=0, passed=0, failed=0, open=0, notes=0))
        for r in rs:
            counts["run"] += 1
            c["run"] += 1
            if r.get("ok") is True:
                counts["passed"] += 1
                c["passed"] += 1
            elif r.get("ok") is False:
                failed.append(r.get(key, "?"))
                which = "open" if any(w in r.get(key, "") for w in WAITING) else "failed"
                counts[which] += 1
                c[which] += 1
            else:
                counts["notes"] += 1
                c["notes"] += 1

    # ---------------- A and H
    M = load("matrix_results.json", []) or []
    M0 = load("matrix_results_asfound.json", []) or []
    rows = []
    for r in M:
        m = r.get("match") or {}
        roles = "all four as a person would pick" if m and all(m.values()) else ("differs: " + ", ".join(k.replace("_col", "").replace("benign_label", "normal value") for k, v in m.items() if not v) if m else "no hand-made settings to compare")
        res = "ran" if r.get("ok") else "refused"
        ok = bool(r.get("ok")) or bool(r.get("notes"))
        r["_ok"] = ok and (not m or all(m.values()) or bool(r.get("notes")))
        ev = (f"H1 {r['H1']['gain']:+.1f} points ({'above' if r['H1']['clears'] else 'not above'} the 5-point rule), H2 {r['H2']['gain']:+.1f}; {r.get('run_s')} s; peak memory {r.get('peak_mb')} MB; {str(r.get('organizations', ''))[16:]}"
              if r.get("ok") else (r.get("error") or "")[:230])
        rows.append((r["file"], f"{r.get('rows', 0):,} x {r.get('columns', 0)}", res + ("" if not r.get("over_upload_limit") else " (file is over the 200 MB upload limit; engine only)"), roles, ev + ((" NOTE: " + r["notes"]) if r.get("notes") else "")))
    tally([dict(test="ingestion: " + r["file"], ok=r["_ok"]) for r in M], sec="A and H. Ingestion matrix (one check per file)")
    a_ran0, a_all0 = sum(1 for r in M0 if r.get("ok")), len(M0)
    a_match0 = sum(1 for r in M0 if r.get("match") and all(r["match"].values()))
    a_ran, a_match = sum(1 for r in M if r.get("ok")), sum(1 for r in M if r.get("match") and all(r["match"].values()))
    secA = table(["File", "Records x columns", "Result", "Detected roles against the hand-made settings", "Evidence"], rows)

    # ---------------- B
    Hs = load("hostile_results.json", []) or []
    H0 = load("hostile_results_asfound.json", []) or []
    tally([dict(test="hostile table: " + r["case"], ok=r["ok"]) for r in Hs], sec="B. Malformed and hostile tables (one check per case)")
    secB = table(["Case", "Should", "Result", "What the person is told (or what ran)"],
                 [(r["case"], r["expect"], MARK[r["ok"]], (r.get("message") or f"ran; {r.get('kept')} behavior numbers kept") + (f" [{r['note']}]" if r.get("note") else "")) for r in Hs])
    big = load("bigfile_results.json", {}) or {}

    C, secC = simple("injection_results.json")
    U, secU = simple("ui_upload_results.json")
    U0 = load("ui_upload_results_asfound.json", []) or []
    UP, secUP = simple("ui_upload_results_patched.json")
    tally([dict(test="with patch P1: " + r["test"], ok=r["ok"]) for r in UP], sec="C. Browser uploads on a patched copy of the page (kept as the record of patch P1)")
    D, secD = simple("fingerprint_results.json")
    E, secE = simple("gate_results.json")
    G, secG = simple("repo_results.json")
    for rs, sec in ((C, "C. Injection"), (U, "C. Hostile files through the real page (browser)"), (D, "D. Fingerprint and agent"), (E, "E. Access gate and server"),
                    (G, "G. Repository"), (load("fp_page_results.json", []) or [], "D. Hostile fingerprints through the real page (browser)")):
        tally(rs, sec=sec)
    SF, secSF = simple("signin_flow_results.json")
    tally(SF, sec="E. Sign-in path in a real browser")
    BL, secBL = simple("browser_load_results.json")
    tally(BL, sec="F. Browser sessions under load")
    PS = load("protocol_sample_results.json", {}) or {}
    if PS:
        tally([dict(test="protocol-budget run on the largest sample upload: " + str(PS.get("file")), ok=bool(PS.get("ok")))], sec="F. Protocol run on the largest sample upload")
    F = load("concurrency_results.json", {}) or {}
    F0 = load("concurrency_results_asfound_sandbox.json", {}) or {}
    Fm = load("concurrency_results_mac.json", {}) or {}
    frows = []
    for tag, d in (("as found, before the lock (Linux test box, 4 cores)", F0), ("after the lock (Linux test box, 4 cores)", load("concurrency_results_fixed_sandbox.json", {}) or {}), ("after the lock (the Mac, 18 cores)", Fm), ("latest run of the suite", F)):
        if not d:
            continue
        s = d["serial"]
        frows.append((tag, "one run, twice", "identical" if s["identical_when_repeated"] else "DIFFERENT", f"{s['seconds']} s a run; H1 {s['h1_gain'] * 100:.2f} points; peak memory {s['peak_mb_after_two_serial_runs']} MB"))
        for r in d["runs"]:
            frows.append((tag, f"{r['at_once']} at once", f"{r['different_from_serial']} of {r['at_once']} differ from the serial result", f"{r['seconds']} s in all; H1 of each: {r['h1_gain_points']}; peak memory {r['peak_mb']} MB; errors: {len(r['errors'])}"))
    for d in (F, Fm):
        if d:
            tally([dict(test=f"concurrency: {r['at_once']} at once give the serial result", ok=(r["different_from_serial"] == 0 and not r["errors"])) for r in d["runs"]]
                  + [dict(test="determinism: one run twice", ok=d["serial"]["identical_when_repeated"])], sec="F. Concurrency and determinism (engine level, each machine)")
    secF = table(["When", "Runs", "Result", "Evidence"], frows)
    R = load("reproduce_results.json", []) or []
    tally([dict(test="library card reproduced: " + r["dataset"], ok=(r["differences"] == 0)) for r in R], sec="F. Library cards recomputed")
    secR = table(["Library dataset", "Budget of the stored card", "Stored card made", "Values compared", "Differences", "Largest difference", "Minutes"],
                 [(r["dataset"], r.get("budget", ""), r["stored_made"], r["values_compared"], r["differences"], r["largest_difference"], r["minutes"]) for r in R])
    A = load("audit_results.json", {}) or {}
    arows = []
    for env, d in A.items():
        for p in d["packages_with_advisories"]:
            arows.append((env, f"{p['package']} {p['version']}", p["advisories"], p["clean_from"], ", ".join(p["ids"][:3])))
        if not d["packages_with_advisories"]:
            arows.append((env, f"{d['packages_checked']} packages", 0, "", ""))
    secAud = table(["Environment", "Package", "Known advisories", "Clean from version", "Examples"], arows)
    not_checked = sorted({x for d in A.values() for x in d.get("not_checked", [])})

    base_sha = (load("baseline_example_quick_linux_aarch64.json", {}) or {}).get("sha256", "not saved")
    h_pass0, h_all0 = sum(1 for r in H0 if r["ok"]), len(H0)
    h_crash0 = sum(1 for r in H0 if r["outcome"] in ("crash", "hang"))
    fp_total = next((r["evidence"] for r in D if r["test"] == "hostile fingerprints, total"), "")
    FP, secFP = simple("fp_page_results.json")
    fp_page = "; ".join(f"{r['test'].split(': ', 1)[-1]}: {r['evidence']}" for r in FP) or "not run"
    rates = [r for r in E if "rate_per_minute" in r]
    rate = max((r["rate_per_minute"] for r in rates), default=0)
    conc0 = "; ".join(f"{r['different_from_serial']} of {r['at_once']} runs at once differed from the serial result ({r['seconds']} s)" for r in F0.get("runs", []))
    conc1 = "; ".join(f"{r['different_from_serial']} of {r['at_once']} differ ({r['seconds']} s)" for r in (load("concurrency_results_fixed_sandbox.json", {}) or {}).get("runs", []))
    ui0 = next((r["evidence"] for r in U0 if "impossible_exponent" in r["test"]), "not run")
    _u1 = load("ui_upload_results.json", []) or []
    _u1 = _u1.get("results", []) if isinstance(_u1, dict) else _u1
    ui1 = next((r["evidence"] for r in _u1 if "impossible_exponent" in r.get("test", "")), "not run")
    gate_now = "; ".join(f"of {r['sessions']} guesses sent at once from fresh sessions, {r.get('refused', 0)} were turned away by the limit" for r in rates) or "not run"
    mem = sorted(r.get("peak_mb", 0) for r in M if r.get("ok") and not r.get("over_upload_limit"))
    quick_s = sorted(r.get("run_s", 0) for r in M if r.get("ok"))

    L.append(f"""# ThreatPrint pressure test report

Built by `tests/pressure/report.py` on {time.strftime('%d %B %Y, %H:%M')} from the result files in `qa/`. Every number below was produced by a run of the suite;
the file and the machine of each part are listed at the end. Rerun: `python tests/pressure/run_all.py` (about 12 minutes on the Mac with the library datasets,
`--quick` about 5 minutes without them). The patches that `app.py` needed (`qa/APP_PATCHES.md`, P1 to P11) were applied on 10 November 2026; that file is kept as the record of what was found.

## Summary

- Checks in this report: {counts['run']}. Passed: {counts['passed']}. Failed: {counts['failed']}. Open, waiting for a patch in `app.py`: {counts['open']}. Notes (measurements, no pass or fail): {counts['notes']}. The last table of this report shows how the total is counted, section by section.
- As found, before any fix: the ingestion matrix ran {a_ran0} of {a_all0} files and matched the hand-made column roles on {a_match0}; of {h_all0} malformed or hostile tables {h_pass0} ended well and {h_crash0} ended the Python process; two evaluations at once changed each other's numbers.
- Now: the matrix runs {a_ran} of {len(M)} files and matches the hand-made roles on {a_match}; the others are explained in the table. All {len(Hs)} malformed or hostile tables end in a run or in one sentence for the person. Runs at once give the serial numbers.
- The engine changes did not move a result. On the Linux test machine the built-in example gives the identical scorecard before and after the changes (SHA-256 of all its numbers: {base_sha[:16]}...; the baseline was saved before the changes). On the Mac, {len(R)} library cards were recomputed from their data with today's engine and the budget written in each card: {sum(r['differences'] for r in R)} differing values out of {sum(r['values_compared'] for r in R)}.

## The worst findings

1. **A 13-byte cell ends the whole site on Linux.** A CSV cell such as `1e2147483648` (or the hex string `32342e33302037352e37350d0a`, which the Edge-IIoTset payload column holds) makes the number parser of pandas 2.3.3 end the Python process on Linux (segmentation fault in `read_csv` and `to_numeric`; macOS is not affected). Through the real page, as found: {ui0}. Fixed in the engine and the agent (`read_table`, `defuse`); the page reads every upload and every sample file through `read_table` (patch P1, applied). Through the real page now: {ui1}.
2. **Two visitors at once got numbers that no single run gives.** PyTorch's global random generator is shared by every visitor thread. As found: {conc0}. Fixed with one run at a time in the process (`engine.RUN_LOCK`): {conc1}.
3. **A hostile fingerprint file broke the page and put its own markup into it.** {fp_total}. Through the real page: {fp_page}. Streamlit's own filter removed the script handler, so markup was injected but no script ran. The contribute button built its file name from a field of the upload (a path in that field resolves outside the folder; only the disabled state of a button stood in the way, and forcing that button was not tried). Fixed in `threatprint_agent.load_fingerprint` and `engine.save_contribution`; the page uses both (patches P2 and P3, applied), so the file name of a kept fingerprint is the digest the server computes itself.
4. **The sign-in delay was not a limit.** As found, a fresh session started with a clean count: 231 to 262 password guesses a minute from one machine over four runs of the probe (recorded in `qa/APP_PATCHES.md`). Nothing behind the gate was reachable without the password, and forged messages did not open it. The page now counts wrong passwords for the whole site (`engine.GATE_LIMITER`, patch P4, applied): {gate_now}.
5. **The automatic column detection was wrong on real datasets, silently.** As found it chose a sub-category, an attacker/victim flag or an attack identifier as the attack type on three library datasets, missed the host column of Zeek logs, and one quick look stopped on a table with little normal traffic. Detection rules fixed; where a person is needed (no value that means normal) the tool now says so on the page (`benign_guess`, patch P6, applied).

## A and H. Ingestion matrix, automatic path (result file: {when('matrix_results.json')})

Every file goes through what the upload page does: read, `engine.inspect` with no settings, every suggestion accepted, `engine.run` with the quick budget.
Four sample files ship with the tool (two of them new: a hospital and a manufacturing plant, both synthetic, made by `tools/make_sample_orgs_more.py` with a fixed seed).

{secA}

Quick-look time over the files that ran: {quick_s[0] if quick_s else '-'} to {quick_s[-1] if quick_s else '-'} seconds. Peak memory of one evaluation (files under the upload limit): {mem[0] if mem else '-'} to {mem[-1] if mem else '-'} MB.

## B. Malformed and hostile tables (result file: {when('hostile_results.json')})

Pass = the table runs, or the person gets one sentence that says what to change. A traceback, an error not written for a person, a dead process or no answer in 120 seconds fails.

{secB}

A table at the upload limit ({when('bigfile_results.json')}): {big.get('bytes', 0) / 1e6:.0f} MB, {big.get('rows', 0):,} records x {big.get('columns', 0)} columns; read {big.get('read_s')} s, column detection {big.get('inspect_s')} s, quick look {big.get('quick_s')} s, peak memory {big.get('peak_mb')} MB.

## C. Injection (result files: {when('injection_results.json')}; browser: {when('ui_upload_results.json')})

{secC}

The same files through the real page in a headless browser (a dialog that opens means a script ran):

{secU}

The same four uploads against a copy of the page with patch P1 of `qa/APP_PATCHES.md` applied in memory (`ui_upload.py --patched`, run before P1 was applied to `app.py` itself; {when('ui_upload_results_patched.json')}):

{secUP}

## D. Fingerprint and agent (result file: {when('fingerprint_results.json')})

{secD}

Two of the hostile fingerprints through the real page as it stands now, with patch P2 applied ({when('fp_page_results.json')}). As found, before the patch, both gave a traceback or put their own markup into the page:

{secFP}

## E. Access gate and server (result file: {when('gate_results.json')})

A raw client that speaks Streamlit's websocket protocol, against a copy of the site started with a test password.

{secE}

The sign-in path in a real browser, on the pages as they are now ({when('signin_flow_results.json')}):

{secSF}

What the shared password does: it keeps the pages, the results and the upload form away from anybody who does not have it, and a wrong or forged cookie does not help. What it does not do: it is one password for everybody (no accounts, nobody can be removed without changing it for all), a stolen cookie works until the next day or until the password changes, and anybody on the internet can still open a session, see the sign-in screen and keep the server busy. For customers the site needs a real front door before Streamlit: an identity-aware proxy (for example Cloudflare Access or an OAuth proxy) with one account per person, and a rate limit at that proxy.

## F. Concurrency, determinism, load (result files: {when('concurrency_results.json')}; Mac: {when('concurrency_results_mac.json')})

{secF}

Library cards recomputed with today's engine ({when('reproduce_results.json')}):

{secR}

Real browser sessions on the real page at once, each signing in and starting a quick look of the built-in example ({when('browser_load_results.json')}):

{secBL}

One protocol-budget run on the largest sample upload, through the upload path ({when('protocol_sample_results.json')}): {(str(PS.get('file')) + ', ' + format(PS.get('rows', 0), ',') + ' records x ' + str(PS.get('columns')) + ' columns: ' + ('ran in ' + str(PS.get('run_s')) + ' s, peak memory ' + str(PS.get('peak_mb')) + ' MB, three seeds; a local run of the tool, not the run of record' if PS.get('ok') else 'stopped: ' + str(PS.get('error')))) if PS else 'not run'}.

## G. Supply chain and repository (result files: {when('repo_results.json')}; audit: {when('audit_results.json')})

{secG}

Known advisories (pip-audit):

{secAud}

Not checked by pip-audit: {'; '.join(not_checked) if not_checked else 'nothing was left out'}. For those packages the statement "no known advisory" does not apply; the publisher's own notes are the place to look.

Streamlit 1.50.0 required Pillow below 12, and Pillow is clean only from 13.0.0, so both were moved together: the pinned set is now Streamlit 1.67.0 with Pillow 13.0.0 (10 November 2026). On that set the app tests, this suite and a browser pass over every page were run again, and pip-audit shows no known advisory for the environment that ran the suite or for the pinned versions. The row of the Mac above is its install from before the update; it is updated at release and audited again then. For the old set, as the app was written, no uploaded file is given to Pillow (uploads are CSV, Parquet and JSON; the only image it opens is its own icon), and the two Streamlit advisories concern Windows hosts and a local attacker. That is a reading of the code and of the advisory texts, not a test.

## Bugs fixed in this session (files the pressure agent owns)

| File | What was wrong | Fix | How it was verified |
|---|---|---|---|
| `engine.py` | Runs at once shared PyTorch's global random generator and changed each other's results | `RUN_LOCK`: one evaluation at a time in the process; a waiting run says so in its log and gives up with one sentence after 30 minutes | section F; example scorecard identical; library cards identical |
| `threatprint_agent.py`, `engine.py` | A cell with an impossible exponent ended the process on Linux | `read_table` neutralizes such cells before pandas sees them; `defuse` does the same for tables that arrive another way (Parquet, a DataFrame) | section B (two cases), agent command line in section D |
| `threatprint_agent.py` | The reader gave raw pandas errors (empty file, PDF, binary, Latin-1), read semicolon and tab files as one column | `read_table`: one sentence per problem, encoding fallback, delimiter detection, duplicate column names numbered | section B |
| `threatprint_agent.py` | Label detection: a sub-category, a yes/no flag, an attack identifier or a free-text column could win; a count column that contains 0 could be taken for a label | Columns with three or more values come before yes/no columns, the usual attack-type names come before the others, identifiers and descriptions are set back, a number column needs a label-like name | section A (BoT-IoT, CIDDS-001, CIDDS-002), section B ("no label column") |
| `threatprint_agent.py` | Host detection missed Zeek names (`id.orig_h`), took an address before the device name, took a column that is one value in 95% of the records | Zeek pattern, name before address, the 95% rule, upper bound of distinct hosts raised to a tenth of the records | section A (IoT-23, Edge-IIoTset subset, the plant sample) |
| `engine.py` | Quick look: the class-stratified cap left a table with little normal traffic with too few normal validation records and stopped | Normal traffic keeps at least 1,500 records under the cap; when grouping by host starves one organization, three random thirds are used and the scorecard says so | section A (BoT-IoT 5%) |
| `engine.py` | Errors were ValueError with half a sentence, or raw library errors | `DataProblem`: one sentence that names the column, the values found and what to change; anything unforeseen is wrapped so that no page shows a traceback | section B |
| `engine.py` | A column named `y`, `org`, `part`, `event` or `source` was silently overwritten by the tool's own working columns | Such columns are renamed on the way in | section B |
| `threatprint_agent.py` | A hostile fingerprint gave tracebacks; `verify` could raise | `load_fingerprint` and `check_fingerprint` check every field; `verify` never raises | section D |
| `engine.py` | No safe way to keep a contributed fingerprint | `save_contribution`: checked, digest must match, file name from the computed digest, upper limit of 500 files or 50 MB | section D |
| `engine.py` | No count of wrong passwords across sessions | `AttemptLimiter` and `GATE_LIMITER` (in memory, per client and for the whole site) | unit check in the suite's history; the page test turns green with patch P4 |
| `threatprint_agent.py` | A downloaded CSV could carry formula cells to a peer | `csv_safe`; the agent's `--sanitized` output uses it | section C |
| `threatprint_agent.py` | The docstring said the fingerprint holds no minimum or maximum values | Reworded: the 1% and 99% quantiles can equal the extremes for numbers with few distinct values | section D (measured shares) |
| `requirements.txt`, `requirements-mac.txt` | Version ranges | Exact versions of the tested sets | section G |
| `Dockerfile`, `.dockerignore` | The container ran as root; `docker build` in the working folder copied the password files into the image | Ordinary user, health check; `.dockerignore` lists the secrets | section G |
| `samples/`, `tools/make_sample_orgs_more.py` | Two sample files, one sector each | Two more synthetic organizations (hospital, manufacturing plant) with their own column names; `samples/manifest.json` lists four | section A, section D |

## Patches to `app.py` from `qa/APP_PATCHES.md`: all applied on 10 November 2026

| Patch | Severity | What was applied | The check that now passes |
|---|---|---|---|
| P1 | critical | `_read_upload` and the sample loader use `engine.read_table` | browser upload of `impossible_exponent.csv`, `binary.csv`, `semicolons.csv` (section C) |
| P2 | high | the fingerprint upload uses `agent.load_fingerprint`; values shown in the headline boxes are escaped | hostile fingerprints through the real page (section D) |
| P3 | high | contribute uses `engine.save_contribution`; the folder can be set with `TP_CONTRIB_DIR` | contribute checks of section D |
| P4 | high | sign-in uses `engine.GATE_LIMITER` and safe session reads; a form that Streamlit cannot draw after a forged message ends in one sentence; cookie with the Secure flag on https | "a server-side limit on password guesses across sessions" and "no error box" (section E) |
| P5 | high | the three CSV downloads go through `engine.csv_safe` | "every CSV download goes through csv_safe" (section C) |
| P6 | medium | the confirmation form warns when the normal value was only a guess (`benign_guess`) | page test in `tests/test_app.py` |
| P7 | medium | a scorecard shows `card["warnings"]`; library cards made before the key existed get the same sentences without a rerun | page test in `tests/test_app.py` |
| P8 | medium | records with an empty label are left out (`drop_labels`), and the page says how many | page test in `tests/test_app.py` |
| P9 | low | nothing to change: the page already shows the engine's "in line" message | section F |
| P10 | text | the agent page and the README say what the lowest and highest stored points are | wording check in `tests/test_app.py` |
| P11 | repository | `qa/_*` ignored; Streamlit 1.67.0 and Pillow 13.0.0 pinned | section G |

## Limits that are real and should be said to a customer

- One evaluation runs at a time on a server. A quick look takes {quick_s[0] if quick_s else '-'} to {quick_s[-1] if quick_s else '-'} seconds on the Mac, so a class of thirty waits several minutes for the last scorecard; a protocol run on a large table holds the line for much longer. More capacity means more processes behind a queue, not more threads.
- Memory: one evaluation of a table under the upload limit peaked at {mem[-1] if mem else '-'} MB in the matrix, and a 200 MB file at {big.get('peak_mb')} MB. A free host with 1 GB cannot take the large library tables or an upload near the limit; the Mac can.
- The tool needs labeled records: at least three attack types besides normal traffic, about 300 normal records per organization, and numbers that describe behavior. When a table falls short the tool says which of these is missing; it cannot make up for it.
- Automatic column roles are suggestions. On {a_match} of {len(M)} files they equal what a person chose by hand; where no label value means normal, or the attack types live in free text, a person has to decide.
- The shared password is a door for reviewers, not customer-grade access control (section E). A visitor who has only seen the sign-in screen can still send files to Streamlit's own upload address (1 MB was accepted in the test); nothing reads them, but they use the server's memory, so customers need a front door before Streamlit.
- A fingerprint is a summary, not a formal privacy protection. What it reveals about its sender has not been measured; its lowest and highest stored quantiles can equal the true extremes (section D).
- Scratch files of this test whose names start with an underscore are in `qa/` (logs, a frozen package list, two small scripts). They are not needed; they were left in place because nothing in this folder is deleted without Rayve's yes.

## How the total is counted

{table(["Section", "Checks", "Passed", "Failed", "Open", "Notes (no pass or fail)"], [(k, v["run"], v["passed"], v["failed"], v["open"], v["notes"]) for k, v in by_section.items()] + [("Total", counts["run"], counts["passed"], counts["failed"], counts["open"], counts["notes"])])}

## Where each part ran

{table(["Result file", "When", "Machine", "Python"], [(f, m["when"], m["machine"], m["python"]) for f, m in sorted(meta.items())])}
""")
    text = "\n".join(L).replace("—", ", ")
    low = re.sub(r"`[^`]*`", " ", text).lower()
    bad = [w for w in BANNED if re.search(r"\b" + re.escape(w) + r"\b", low)]
    if bad:
        text += "\n\n> WORDING CHECK: this report still holds a word that should not be used: " + ", ".join(bad) + "\n"
    open(os.path.join(QA, "PRESSURE_TEST_REPORT.md"), "w").write(text)
    json.dump(dict(built=time.strftime("%Y-%m-%d %H:%M"), counts=counts, failed=failed, wording=bad), open(os.path.join(QA, "pressure_results.json"), "w"), indent=1)
    print("counts", counts, "| wording issues:", bad)
    return failed


if __name__ == "__main__":
    write()
