"""The fast parts of the pressure suite as ordinary tests:   python -m pytest tests/pressure -q   (about two minutes)

Hostile tables (each in its own process), hostile fingerprints, the contribute path, the password limiter, the CSV
safety helper, the run lock. The slow parts (library datasets, the 200 MB file, the raw-client probe of the gate, the
browser) are in run_all.py.
"""
import copy
import io
import json
import os
import subprocess
import sys
import threading

import pandas as pd
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import common  # noqa: E402,F401
import engine  # noqa: E402
import hostile  # noqa: E402
import threatprint_agent as agent  # noqa: E402


@pytest.mark.parametrize("name", list(hostile.CASES))
def test_hostile_table(name):
    """Runs, or is refused with one sentence written for a person; never a traceback, a dead process or a hang."""
    p = subprocess.run([sys.executable, os.path.join(HERE, "hostile.py"), "--one", name], capture_output=True, text=True, timeout=hostile.LIMIT_S, cwd=HERE)
    line = [x for x in p.stdout.splitlines() if x.startswith("RESULT ")]
    assert line, f"the process died (exit code {p.returncode})"
    r = json.loads(line[-1][7:])
    expect = hostile.CASES[name][1]
    if expect == "run":
        assert r["outcome"] == "ran", r.get("message")
    else:
        assert r["outcome"] == "refused" and r["human"], r.get("message")


def _fingerprint():
    df = engine.example_data()
    roles = agent.inspect(df)
    return agent.build_fingerprint(df, roles["label_col"], roles["benign_label"], roles["numbers"], source_col=roles["source_col"], time_col=roles["time_col"])


def test_reader_never_dies_on_the_impossible_exponent():
    df = agent.read_table(io.BytesIO(b"a,b,attack_type\n1e2147483648,1,dos\n32342e33302037352e37350d0a,2,scan\n3,3,normal\n"), "x.csv")
    assert df["a"].tolist()[:2] == ["~1e2147483648", "~32342e33302037352e37350d0a"] and df.attrs["notes"]
    assert pd.to_numeric(df["a"], errors="coerce").notna().sum() == 1


@pytest.mark.parametrize("data", [b"", b"[1,2]", b"\"x\"", b"{}", b"{\"format\": \"threatprint-fingerprint\"}", b"\xff\xfe\x00", b"[" * 50000 + b"]" * 50000,
                                  b"{\"format\":\"threatprint-fingerprint\",\"pad\":\"" + b"x" * 6_000_000 + b"\"}"])
def test_hostile_fingerprint_is_refused_in_one_sentence(data):
    with pytest.raises(agent.DataProblem):
        agent.load_fingerprint(data)


def test_fingerprint_fields_are_typed_and_tampering_is_seen():
    fp = _fingerprint()
    assert agent.verify(agent.load_fingerprint(json.dumps(fp).encode()))
    for change in (lambda f: f.update(removed_columns_count="<img src=x onerror=alert(1)>"), lambda f: f.update(payload_bytes="1"), lambda f: f.update(classes=[]),
                   lambda f: f["integrity"].update(digest="../../etc/passwd"), lambda f: f.update(hosts={"a": 1}), lambda f: f["normal"].update(records=True)):
        bad = copy.deepcopy(fp)
        change(bad)
        with pytest.raises(agent.DataProblem):
            agent.check_fingerprint(bad)
    moved = copy.deepcopy(fp)
    moved["normal"]["records"] += 10
    assert agent.check_fingerprint(moved) and not agent.verify(moved)
    assert agent.verify(None) is False and agent.verify({"format": agent.FORMAT, "integrity": 5}) is False


def test_contribution_is_named_by_the_computed_digest_and_has_an_upper_limit(tmp_path):
    fp = _fingerprint()
    name = engine.save_contribution(copy.deepcopy(fp), str(tmp_path))
    assert name == agent.digest(fp)[:16] + ".json" and os.listdir(tmp_path) == [name]
    evil = copy.deepcopy(fp)
    evil["integrity"]["digest"] = "../../../../tmp/tp_pwned"
    with pytest.raises(agent.DataProblem):
        engine.save_contribution(evil, str(tmp_path))
    other = copy.deepcopy(fp)
    other["removed_columns_count"] = 99
    other["integrity"]["digest"] = agent.digest(other)
    with pytest.raises(agent.DataProblem):
        engine.save_contribution(other, str(tmp_path), max_files=1)
    assert len(os.listdir(tmp_path)) == 1


def test_password_limiter_counts_across_sessions():
    t = [1000.0]
    lim = engine.AttemptLimiter(per_client=3, window_s=60, lock_s=120, site_per_minute=10, clock=lambda: t[0])
    for _ in range(3):
        assert lim.wait("a") == 0
        lim.failed("a")
        t[0] += 1
    assert lim.wait("a") > 100 and lim.wait("b") == 0          # the guesser waits, another client does not
    t[0] += 130
    assert lim.wait("a") == 0
    for i in range(10):
        lim.failed(f"client-{i}")                                # ten clients, one wrong password each
    assert lim.wait("somebody new") > 0                          # the whole site slows down
    t[0] += 61
    assert lim.wait("somebody new") == 0
    lim.failed("z")
    lim.passed("z")
    assert lim.wait("z") == 0


def test_csv_safe_stops_formula_cells_and_keeps_numbers():
    df = pd.DataFrame({"=1+1": [1.5, -2.0], "label": ["=HYPERLINK(1)", "@x"], "ok": ["plain", "-dash"]})
    out = pd.read_csv(io.StringIO(agent.csv_safe(df).to_csv(index=False)), dtype=str, header=None, keep_default_na=False)
    cells = [c for row in out.itertuples(index=False) for c in row]
    assert not [c for c in cells if c[:1] in ("=", "@")] and "'-dash" in cells and "-2.0" in cells


def test_two_evaluations_at_once_give_the_serial_scorecard():
    import baseline
    ref = baseline.fingerprint(baseline.numbers(baseline.example_card()))
    got = [None, None]

    def work(i):
        got[i] = baseline.fingerprint(baseline.numbers(baseline.example_card()))

    th = [threading.Thread(target=work, args=(i,)) for i in range(2)]
    [x.start() for x in th]
    [x.join() for x in th]
    assert got == [ref, ref]
    saved = baseline.baseline_file()
    if os.path.exists(saved):
        assert json.load(open(saved))["sha256"] == ref           # the scorecard of the example has not moved since the baseline was saved


def test_library_settings_with_a_label_map_still_load():
    """A hand-made settings file may rename the raw normal value (CIDDS: '---' to 'normal'); the check for the normal value comes after."""
    df = hostile.base()
    df["attack_type"] = df.attack_type.replace({"normal": "---"})
    cfg = dict(name="t", label_col="attack_type", benign_label="normal", label_map={"---": "normal"}, source_col="device_ip", time_col="timestamp", drop=["src_port"])
    card = engine.run(cfg, frame=df, budget=engine.Budget(**hostile.TINY))
    assert card["benign"] == "normal" and "warnings" in card
