# Security

ThreatPrint is research software built on a doctoral praxis. This page says how to report a problem, what the built-in
access control does and does not do, and what a deployment for customers needs. Every number below comes from the pressure
suite of this repository (`qa/PRESSURE_TEST_REPORT.md`, `python tests/pressure/run_all.py`).

## Reporting a problem

Please do not open a public issue for a security problem. Use GitHub's private report on this repository
(Security tab, "Report a vulnerability"). Say what you did, what happened and what you expected. Reports are read by the
author; this is a small project and there is no stated response time.

## What is processed and what is kept

- An uploaded table is read into memory for the visitor's session and is gone when the session ends. It is not written to
  disk by the tool.
- A fingerprint (summary statistics per attack type, written by the local agent) is kept on the machine that runs the site
  only when the person ticks the consent box and presses "Contribute this fingerprint". The file is checked field by field,
  its integrity digest must match, the file name is the digest the server computes itself, and the folder stops at 500 files
  or 50 MB.
- Sanitized means direct identifiers removed, nothing more. The behavior numbers that remain can still point to a device:
  on the study dataset a receiving peer traced sanitized attack records to their source device 41% to 55% of the time
  against 7% to 35% by guessing. The tool measures this; it does not prevent it.
- The local agent (`threatprint_agent.py`) has no network code. It writes files next to the input and sends nothing.

## The shared password: what it does and what it does not do

The hosted copy asks for one shared password (`TP_PASSWORD`, or `[access] password` in `.streamlit/secrets.toml`; neither
is ever committed).

What it does (measured, section E of the report):

- Without the password a visitor is sent the sign-in screen and nothing of the pages, also when asking for pages by name
  or sending forged session values over the websocket.
- A made-up cookie, the cookie of another password, an empty cookie and a cookie from two days ago are refused. After the
  password is changed, a cookie made with the old password no longer admits.
- Wrong passwords are counted for the whole site, not per browser session: 5 wrong tries from one client in 5 minutes,
  then 5 minutes of waiting; 30 wrong tries a minute over the whole site, then the rest of that minute. In the test, of 30
  guesses sent at once from fresh sessions, 30 were turned away. Before this count existed, 231 to 262 guesses a minute
  from one machine were measured.

What it does not do:

- It is one password for everybody. There are no accounts, and nobody can be removed without changing it for all.
- A stolen cookie works until the next day or until the password changes.
- The client is told apart by the address the proxy reports. Without a trusted proxy in front, that address can be made
  up, and then only the site-wide count applies.
- Anybody on the internet can still open a session and see the sign-in screen. A visitor who has only seen that screen can
  send files to Streamlit's own upload address (1 MB was accepted in the test). Nothing reads such a file, but it uses the
  server's memory; the upload limit per file (200 MB) is the only bound.
- The count of wrong passwords lives in memory: a restart of the site clears it.

The shared password is a door for reviewers. It is not access control for customers.

## What a deployment for customers needs

- An identity-aware proxy in front of the app (for example Cloudflare Access or an OAuth proxy): one account per person,
  a rate limit at the proxy, and the app reachable only through it.
- TLS at the proxy. The session cookie is set with the Secure flag when the page is served over https.
- One evaluation runs at a time per process (results stay identical to a serial run). More capacity means more processes
  behind a queue.
- Memory: a 200 MB table peaked at about 1.8 GB in the test, so a host with 1 GB cannot take uploads near the limit.
- Run the container as it is built (ordinary user, no secrets inside the image; `.dockerignore` lists them).

## What the suite checks on every change

- `python -m pytest tests -q`: the pages, the engine, the sign-in limit, and the fast part of the pressure suite (hostile
  and malformed tables, hostile fingerprints, formula cells in downloads, two evaluations at once).
- `python tests/pressure/run_all.py`: the whole pressure suite, including the ingestion matrix over the sample files and
  the dataset library, a 200 MB table, the sign-in probe, the browser uploads and the dependency audit (pip-audit).
- GitHub: the tests on every push, CodeQL for Python, Dependabot for the Python packages and the workflow actions.

## Supported versions

Only the newest commit of the main branch is maintained.
