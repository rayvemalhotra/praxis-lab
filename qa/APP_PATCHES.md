# Patches for app.py (and two text fixes) that the pressure test is waiting for

**Status: all applied on 10 November 2026 (P1 to P8, P10, P11; P9 needed no change). The pressure report shows 0 open and 0 failed. This file is kept as the record of what was found.**

The pressure agent does not edit `app.py`, `ui.py` or `tests/test_app.py`. Everything below is in files it owns
(`engine.py`, `threatprint_agent.py`) and already tested there; `app.py` only has to call it. Function names and the
quoted lines are from `app.py` as it stood on 10 November 2026 around 00:30; line numbers move, so search for the quoted text.
After applying, run `python tests/pressure/run_all.py --quick`: the rows marked "waits for a patch" must turn to pass.

Severity: **critical** = one visitor can take the site down;
**high** = wrong results or a write outside the intended folder; **medium** = a traceback or a misleading page; **low** = polish.

## P1 (critical). The upload reader: one small file ends the whole site on Linux

`_read_upload` calls pandas directly. A CSV cell such as `1e2147483648` makes the number parser of pandas 2.3.3 end the
Python process on Linux (segmentation fault; measured in the sandbox, not on macOS). Seen through the real page:
`qa/ui_upload_results_asfound.json`, "server alive: False". The same reader also gives raw pandas errors for an empty
file, a PDF, a binary file, a Latin-1 file, and reads a semicolon file as one column.

Replace the function body:

```python
def _read_upload(up):
    """The uploaded table, read by the safe reader (engine.read_table): never a traceback, never a dead process."""
    df = engine.read_table(up, up.name)
    for note in df.attrs.get("notes", []):
        st.caption(f"Note: {note}.")
    return df
```

and the sample loader `_sample_frame(path, mtime)` (it reads files from `samples/`):

```python
    return engine.read_table(path)
```

The callers already do `except Exception as e: st.error(f"The file could not be read: {e}")`; `engine.DataProblem`
messages are sentences ("the file is a PDF document, not a CSV table; export the records as CSV ..."), so the text reads well.
If the page caches frames with `st.cache_data`, nothing changes: `read_table` returns an ordinary DataFrame.

## P2 (high). Fingerprint upload: a hostile file gave tracebacks and put its own markup into the page

`page_agent` does `fp = json.loads(up.getvalue().decode("utf-8"))` and then trusts every field. `ui.stats` puts its
values into the page unescaped, so `"removed_columns_count": "<img src=x onerror=alert(1)>"` puts that image tag into
the page. Through the real page (`qa/fp_page_results.json`): the element arrived, Streamlit's own filter removed its
script handler, no script ran; so this is injected markup (a fake link or form could be shown), not script execution.
12 other hostile files ended in a traceback (`qa/fingerprint_results.json`). Replace the try block that parses the upload:

```python
        try:
            fp = agent.load_fingerprint(up.getvalue())        # every field checked; one sentence when it is not a fingerprint
        except agent.DataProblem as e:
            st.error(f"This file could not be used: {e}.")
            fp = None
```

and delete the later `if fp is not None and fp.get("format") not in agent.FORMATS:` branch (the check is inside
`load_fingerprint`). After this every value shown is of the right type (whole numbers, short text), and text is escaped by
`esc`, `ui.chip` and `ui.table` as today.

Defence in depth in `ui.stats` (design agent's file): escape the value unless it is marked as HTML, or keep it as is and
never pass anything but numbers the page computed itself.

## P3 (high). "Contribute this fingerprint" wrote to a path taken from the upload

The file name came from `fp['integrity']['digest'][:16]`, a field of the uploaded file (`../../../../tmp/x` resolves outside
the folder), guarded only by a disabled button, and the folder could grow without limit. Replace the body of the
`if st.button("Contribute this fingerprint", ...)` block:

```python
                try:
                    engine.save_contribution(fp, os.path.join(HERE, "contributions"))
                    st.success("Kept on the machine that runs this site. Thank you.")
                except engine.DataProblem as e:
                    st.error(f"Not kept: {e}.")
```

`save_contribution` checks the fingerprint again, requires the digest to match, names the file from the digest it
computes itself, and stops at 500 files or 50 MB.

## P4 (high). Sign-in: no limit across sessions, and forged messages break the form

Measured (`qa/gate_results.json`): the delay after a wrong password lives in one session, and every fresh session
starts clean: 231 to 262 guesses a minute from one machine over four runs of the probe. Forged widget values (`_access_ok`, `_access_attempts`) do not
open the site, but they make the sign-in screen show an error box in the forger's own session. In `gate()`:

```python
def _ss(key, default=None):
    """A session value that only this script sets; a forged widget message of the same name must not break the page."""
    try:
        return st.session_state.get(key, default)
    except Exception:
        return default


def _client():
    """Who is knocking: the address the tunnel or proxy reports, else the socket address."""
    try:
        h = st.context.headers
        return (h.get("Cf-Connecting-Ip") or (h.get("X-Forwarded-For") or "").split(",")[0].strip() or st.context.ip_address or "unknown")
    except Exception:
        return "unknown"
```

Use `_ss("_access_ok")`, `_ss("_left")`, `_ss("_access_attempts", 0)` in place of the three `st.session_state.get(...)`
reads (keep `int(...)` inside a try that falls back to 0), and wrap the password check:

```python
            if ok:
                wait = engine.GATE_LIMITER.wait(_client())
                if wait:
                    st.error(f"Too many wrong passwords were tried. Wait {wait} seconds and try again.")
                elif hmac.compare_digest(given.strip().encode(), pw.encode()):
                    engine.GATE_LIMITER.passed(_client())
                    ...   # as today
                else:
                    engine.GATE_LIMITER.failed(_client())
                    ...   # as today
```

The words "Too many wrong passwords" are what `tests/pressure/gate_probe.py` looks for. Limits (in `engine.AttemptLimiter`):
5 wrong tries per client in 5 minutes, then 5 minutes of waiting; 30 wrong tries a minute over the whole site, then the
rest of that minute. People who already hold the day's cookie are not affected.

Also in `_set_cookie`: add `Secure` when the page is served over https:
`document.cookie = 'tp_access=...; path=/; max-age=...; SameSite=Lax' + (location.protocol === 'https:' ? '; Secure' : '')`.

## P5 (high). CSV downloads: formula cells

Label values and column names come from the uploader; a peer who opens "the sanitized table" in a spreadsheet program
runs any cell that starts with `=`, `+`, `-` or `@` as a formula (961 such cells in the test table). Three places:

```python
tbl.to_csv(index=False)          ->  engine.csv_safe(tbl).to_csv(index=False)          # download_buttons
san.to_csv(index=False)          ->  engine.csv_safe(san).to_csv(index=False)          # _evaluate_body and _sanitize_body
```

## P6 (medium). The page must say when "normal" was only a guess

`engine.inspect` now returns `benign_guess` (True when no label value looks like normal, benign, clean, clear, none, 0
or dashes, and the most frequent value was taken). RT-IoT2022 runs with a DoS class as "normal" without a word. In
`_confirm_columns`, after the selectbox for the normal value:

```python
    if ins.get("benign_guess") and label_col == ins["label_col"]:
        st.warning(f"No label value looks like normal traffic. '{benign}' is only the most frequent value. Pick the value that means normal traffic before you run.")
```

and in the live demo's role reasons, the same sentence where the normal value is explained.

## P7 (medium). Show the warnings of a scorecard

`engine.run` now adds `card["warnings"]`: sentences about few test records of a withheld type, few normal validation
records, a random split, random thirds, a quick look. In `show_card`, under the header band:

```python
    for w in card.get("warnings", []):
        H(f"<div class='tp-note'><p>{esc(w)}</p></div>")
```

(The 25 library cards were made before this key existed and show none; they can be given the key without a rerun:
`card["warnings"] = engine.warnings_for(card)` in `load_cards`.) The quick-look `st.warning` in `show_card` then repeats the
last sentence and can go.

## P8 (medium). Missing labels become an attack type called "nan"

A record with an empty label is read as the label `nan` and treated as an attack type. In `_confirm_columns`, build the
settings with `drop_labels=["nan"]` when `df[label_col].isna().any()`, and say how many records were left out.

## P9 (low). While another evaluation runs

`engine.run` now runs one evaluation at a time in the process and writes to the log
"Another evaluation is running on this server. Yours is in line and starts by itself." The page shows the log already
(`log_box.write`), so nothing has to change. After 30 minutes in line the run ends with
"the server is busy with other evaluations; try again in a few minutes", shown by the existing "The run stopped" message.

## P10 (text). "no minimum or maximum values" is not true as written

Measured on the four sample files: the lowest stored quantile (1%) equals the true smallest value of an attack type's
behavior number in 24% to 61% of the pairs, the highest (99%) equals the true largest in 8% to 54% (counts that are
mostly 0, flags). Change the sentence in `page_agent` ("What it does not hold ...") and in `README.md` to:

> No rows, no device names, no addresses, no ports, no time stamps. The lowest and highest points it stores are the 1%
> and 99% quantiles, not the extremes; for a number with few distinct values (a count that is mostly 0) they can equal
> the smallest or largest value.

The docstring of `threatprint_agent.py` already says this. Any test or page text that says "no minimum or maximum values" must follow.

## P11 (repository, not app.py)

- `.gitignore`: add `qa/_*` (scratch files and server logs of the pressure suite).
- Streamlit 1.50.0 and the Pillow 11.3.0 it requires have known advisories (pip-audit, report section G). Clearing them
  means Streamlit 1.54 or newer and Pillow 13; the pages and the styling must be checked again after that step, so it is
  left as a decision.
- `tests/test_app.py`: add the pressure suite's fast parts to CI if wanted: `python tests/pressure/run_all.py --quick --ci`.
