"""Section E: the access gate and the server, tested from outside with a raw client (no browser): what can somebody who
does not have the password reach, how fast can they guess, can they talk their way past the gate.

The probe starts its own copy of the site on port 8781 with a test password, speaks Streamlit's own protocol over the
websocket (protobuf messages), and reads what the server sends back.

    python tests/pressure/gate_probe.py        writes qa/gate_results.json
"""
import asyncio
import hashlib
import hmac
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

from common import ROOT, save

PORT = int(os.environ.get("TP_PROBE_PORT", "8781"))
PW = "probe-" + hashlib.sha256(os.urandom(8)).hexdigest()[:10]
BASE = f"http://127.0.0.1:{PORT}"
results = []


def add(test, ok, evidence):
    results.append(dict(test=test, ok=ok, evidence=evidence))
    print({True: "PASS", False: "FAIL", None: "NOTE"}[ok], test[:104].ljust(104), "|", str(evidence)[:190], flush=True)


def token(pw, day=None):
    day = day if day is not None else int(time.time() // 86400)
    return hmac.new(pw.encode(), f"threatprint-{day}".encode(), hashlib.sha256).hexdigest()[:40]


def http(path):
    try:
        r = urllib.request.urlopen(urllib.request.Request(BASE + path), timeout=10)
        return r.status, r.read(400)
    except urllib.error.HTTPError as e:
        return e.code, b""
    except Exception as e:  # noqa
        return -1, str(e).encode()


async def talk(steps=(), cookie=None, page=None, timeout=40):
    """One visitor session. steps: list of dicts widget_id -> value sent one after the other (a rerun each).
    Returns for the opening run and each step: dict(texts, gated, ids, seconds)."""
    import tornado.httpclient
    import tornado.websocket
    from streamlit.proto.BackMsg_pb2 import BackMsg
    from streamlit.proto.ForwardMsg_pb2 import ForwardMsg
    headers = {"Origin": BASE}
    if cookie:
        headers["Cookie"] = cookie
    ws = await tornado.websocket.websocket_connect(tornado.httpclient.HTTPRequest(f"ws://127.0.0.1:{PORT}/_stcore/stream", headers=headers), subprotocols=["streamlit"])
    out = []

    async def run(states):
        b = BackMsg()
        b.rerun_script.query_string = ""
        if page:
            b.rerun_script.page_name = page
        for wid, val in (states or {}).items():
            w = b.rerun_script.widget_states.widgets.add()
            w.id = wid
            if isinstance(val, bool):
                w.bool_value = val
            elif isinstance(val, int):
                w.int_value = val
            elif val == "__trigger__":
                w.trigger_value = True
            else:
                w.string_value = str(val)
        t = time.time()
        await ws.write_message(b.SerializeToString(), binary=True)
        texts, ids, n = [], {}, 0
        while True:
            try:
                msg = await asyncio.wait_for(ws.read_message(), timeout)
            except asyncio.TimeoutError:
                break
            if msg is None:
                break
            f = ForwardMsg()
            f.ParseFromString(msg)
            kind = f.WhichOneof("type")
            if kind == "delta" and f.delta.WhichOneof("type") == "new_element":
                el = f.delta.new_element
                which = el.WhichOneof("type")
                n += 1
                if which == "markdown":
                    texts.append(el.markdown.body)
                elif which == "text_input":
                    ids["text:" + el.text_input.label] = el.text_input.id
                    texts.append("[text_input] " + el.text_input.label)
                elif which == "button":
                    ids["button:" + el.button.label] = el.button.id
                elif which == "page_link":
                    texts.append("[page_link] " + el.page_link.label)
                elif which in ("alert", "exception"):
                    texts.append(f"[{which}] " + (el.alert.body if which == "alert" else el.exception.message))
            elif kind == "script_finished":
                if f.script_finished == 2:            # the script asked for a rerun of itself (after a right password): read the next run
                    texts, n = [], 0
                    continue
                break
        joined = "\n".join(texts)
        return dict(texts=joined, gated=("[text_input] Access password" in joined), inside=("[page_link] " in joined), ids=ids or None, elements=n, seconds=round(time.time() - t, 2))

    out.append(await run(None))
    known = out[0]["ids"] or {}
    for st_ in steps:
        states = {}
        for k, v in st_.items():
            states[known.get(k, k)] = v
        out.append(await run(states))
    ws.close()
    return out


async def upload_without_password(size=1_000_000):
    """Can a visitor who has only seen the sign-in screen push a file into the server? Streamlit's upload address needs a
    live session (every visitor has one) and its anti-forgery token (handed to every visitor)."""
    import http.cookiejar
    import tornado.httpclient
    import tornado.websocket
    from streamlit.proto.BackMsg_pb2 import BackMsg
    from streamlit.proto.ForwardMsg_pb2 import ForwardMsg
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    opener.open(BASE + "/_stcore/health", timeout=10).read()
    opener.open(BASE + "/_stcore/host-config", timeout=10).read()
    xsrf = next((c.value for c in jar if "xsrf" in c.name.lower()), "")
    ws = await tornado.websocket.websocket_connect(tornado.httpclient.HTTPRequest(f"ws://127.0.0.1:{PORT}/_stcore/stream", headers={"Origin": BASE}), subprotocols=["streamlit"])
    b = BackMsg()
    b.rerun_script.query_string = ""
    await ws.write_message(b.SerializeToString(), binary=True)
    sid = ""
    for _ in range(60):
        msg = await asyncio.wait_for(ws.read_message(), 20)
        f = ForwardMsg()
        f.ParseFromString(msg)
        if f.WhichOneof("type") == "new_session":
            sid = f.new_session.initialize.session_id
            break
    boundary = "tpboundary123"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x.csv\"\r\nContent-Type: text/csv\r\n\r\n").encode() + b"a" * size + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(f"{BASE}/_stcore/upload_file/{sid}/probe-file-1", data=body, method="PUT",
                                 headers={"Content-Type": f"multipart/form-data; boundary={boundary}", "X-Xsrftoken": xsrf, "Origin": BASE})
    try:
        code = opener.open(req, timeout=30).status
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception as e:  # noqa
        code = f"{type(e).__name__}"
    ws.close()
    return code, bool(sid), bool(xsrf)


def start_server(pw):
    env = dict(os.environ, TP_PASSWORD=pw)
    for k in ("TP_OPEN", "TP_PAGE", "PRAXIS_LAB_OPEN", "PRAXIS_LAB_PAGE", "PRAXIS_LAB_PASSWORD"):
        env.pop(k, None)
    srv = subprocess.Popen([sys.executable, "-m", "streamlit", "run", "app.py", "--server.port", str(PORT), "--server.address", "127.0.0.1", "--server.headless", "true"],
                           cwd=ROOT, env=env, stdout=open(os.path.join(ROOT, "qa", "_gate_server.log"), "w"), stderr=subprocess.STDOUT)
    for _ in range(60):
        time.sleep(1)
        if http("/_stcore/health")[0] == 200:
            return srv
    srv.terminate()
    raise RuntimeError("the test server did not start")


async def probe():
    # ---- what answers without the password
    for path, want, why in [("/_stcore/health", 200, "Streamlit's own health answer ('ok'); no content of the site"),
                            ("/_stcore/host-config", 200, "Streamlit's own settings for the browser; no content of the site"),
                            ("/app/static/inter-latin-wght-normal.woff2", 200, "a typeface; the static folder is public by design and must hold nothing else")]:
        code, _ = http(path)
        add(f"without the password: GET {path}", code == want, f"HTTP {code}; {why}")
    leaks = []
    for path in ["/app/static/../.streamlit/secrets.toml", "/app/static/..%2f.streamlit%2fsecrets.toml", "/app/static/%2e%2e/%2e%2e/.streamlit/secrets.toml",
                 "/app/static/../app.py", "/app/static/..%2fACCESS_PASSWORD.txt", "/app/static/....//ACCESS_PASSWORD.txt", "/.streamlit/secrets.toml", "/ACCESS_PASSWORD.txt",
                 "/app/static/../results/datasense.json", "/app/static/..%2fcontributions%2f", "/app.py", "/.git/config", "/app/static/..%5c.streamlit%5csecrets.toml"]:
        code, body = http(path)
        if code == 200 and (b"password" in body.lower() or b"[access]" in body or b"import " in body or b"[core]" in body or b'"companies"' in body):
            leaks.append(path)
    add("without the password: 13 tries to read files of the site (secrets, the password file, code, results, .git) through the web server", not leaks, leaks or "none of them returned a file")
    static = sorted(os.listdir(os.path.join(ROOT, "static")))
    add("the public static folder holds only typefaces and their licence texts", all(f.endswith((".woff2", ".txt")) for f in static), static)

    # ---- the websocket: what a session without the password is sent
    r = (await talk())[0]
    inside = [m for m in ("[page_link] Results", "Run the evaluation", "attack-class recall", "Download the agent") if m.lower() in r["texts"].lower()]
    add("without the password: a websocket session is sent the sign-in screen and nothing of the pages", r["gated"] and not inside, f"{r['elements']} elements sent; page content found: {inside or 'none'}")
    for page in ("results", "evaluate", "agent", "demo", "research"):
        r = (await talk(page=page))[0]
        if not r["gated"]:
            add(f"without the password: asking for the page '{page}' directly", False, "page content was sent")
            break
    else:
        add("without the password: asking for five pages by name over the websocket", True, "each time only the sign-in screen came back")

    # ---- talking past the gate: widget values a real browser would never send
    forged = [{"_access_ok": True}, {"_access_ok": "true"}, {"_access_ok": 1}, {"_left": False, "_access_ok": True}, {"_access_attempts": -100000}]
    bad, boxes = [], 0
    for f in forged:
        rr = await talk(steps=[f])
        if rr[1]["inside"]:
            bad.append(f)
        boxes += "[exception]" in rr[1]["texts"]
    add("without the password: forged session values sent over the websocket (_access_ok, _left, _access_attempts) do not open the site", not bad,
        bad or "5 forgeries, no page content came back")
    add("the same forgeries leave the sign-in screen working (no error box)", boxes == 0,
        f"{boxes} of 5 forgeries made the sign-in screen show an error box in the forger's own session (nothing is exposed; patch in qa/APP_PATCHES.md)" if boxes else "the sign-in form came back each time")

    # ---- cookies
    for name, cookie, want in [("a made-up cookie", "tp_access=" + "a" * 40, True), ("the cookie of another password", "tp_access=" + token("not-the-password"), True),
                               ("an empty cookie", "tp_access=", True), ("a cookie of 100,000 characters", "tp_access=" + "f" * 100000, True),
                               ("the genuine cookie of today", "tp_access=" + token(PW), False), ("the genuine cookie of yesterday", "tp_access=" + token(PW, int(time.time() // 86400) - 1), False),
                               ("the genuine cookie of two days ago", "tp_access=" + token(PW, int(time.time() // 86400) - 2), True)]:
        try:
            r = (await talk(cookie=cookie))[0]
            add(f"cookie: {name}", r["gated"] == want, "sign-in screen" if r["gated"] else "admitted")
        except Exception as e:  # noqa
            add(f"cookie: {name}", want, f"connection refused ({type(e).__name__})")

    # ---- what a visitor without the password can still make the server do
    try:
        code, sid, xsrf = await upload_without_password()
        add("without the password: sending a 1 MB file to Streamlit's upload address from a session that only saw the sign-in screen", None,
            f"HTTP {code} (204 = the server took the bytes into memory). Session obtained: {sid}; anti-forgery token obtained: {xsrf}. Nothing reads such a file, "
            "but the gate does not stop it: the per-file upload limit (200 MB) is the only bound, so a front door before Streamlit is needed for customers")
    except Exception as e:  # noqa
        add("without the password: sending a file to Streamlit's upload address", None, f"the probe could not finish ({type(e).__name__}: {str(e)[:100]})")

    # ---- the password itself, and how fast it can be guessed
    r = await talk(steps=[{"text:Access password": PW, "button:Enter": "__trigger__"}])
    add("the right password over the websocket admits (so the probe can tell the two states apart)", r[0]["gated"] and r[1]["inside"] and not r[1]["gated"],
        f"after the password: {r[1]['elements']} elements, navigation links present: {r[1]['inside']}")
    r = await talk(steps=[{"text:Access password": "wrong-%d" % i, "button:Enter": "__trigger__"} for i in range(4)])
    secs = [x["seconds"] for x in r[1:]]
    add("wrong guesses in ONE session are slowed down more each time", all(x["gated"] for x in r[1:]) and secs[-1] > secs[0], f"seconds per guess: {secs}")
    for n in (10, 30):
        t = time.time()
        rs = await asyncio.gather(*[talk(steps=[{"text:Access password": "guess-%d" % i, "button:Enter": "__trigger__"}]) for i in range(n)], return_exceptions=True)
        took = time.time() - t
        done = sum(1 for x in rs if not isinstance(x, Exception) and not x[1]["inside"])
        refused = sum(1 for x in rs if not isinstance(x, Exception) and "too many" in x[1]["texts"].lower())
        rate = done / took * 60
        results.append(dict(test=f"guessing with {n} fresh sessions at once", ok=None, rate_per_minute=round(rate), sessions=n, seconds=round(took, 1), refused=refused,
                            evidence=f"{done} guesses answered in {took:.1f} s = {rate:,.0f} guesses a minute from one machine; {refused} were turned away by a server-side limit"))
        print("NOTE", results[-1]["test"], "|", results[-1]["evidence"], flush=True)


def main():
    srv = start_server(PW)
    try:
        asyncio.run(probe())
        # ---- a password change makes yesterday's cookie worthless
        srv.terminate()
        srv.wait(timeout=20)
        srv2 = start_server(PW + "-changed")
        try:
            r = asyncio.run(talk(cookie="tp_access=" + token(PW)))[0]
            add("after the owner changes the password, a cookie made with the old password no longer admits", r["gated"], "sign-in screen" if r["gated"] else "admitted")
        finally:
            srv2.terminate()
    finally:
        try:
            srv.terminate()
        except Exception:
            pass
    rates = [r for r in results if "rate_per_minute" in r]
    limited = any(r.get("refused") for r in rates)
    add("a server-side limit on password guesses across sessions", limited, "guesses from fresh sessions are turned away after a few failures" if limited else
        f"none: every fresh session starts with a clean count, so the delay is no limit at all ({max(r['rate_per_minute'] for r in rates):,} guesses a minute measured). "
        "The random 16-character password makes guessing hopeless anyway; a password a person chose would not be safe behind this gate. Patch in qa/APP_PATCHES.md")
    save("gate_results.json", results)
    return results


if __name__ == "__main__":
    main()
