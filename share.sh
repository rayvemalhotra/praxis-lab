#!/bin/sh
# Put ThreatPrint on a public https link with a password (Cloudflare quick tunnel, no account needed).
#
# Visitors are never served the files that are being worked on. They are served a pinned copy of the code:
# the git worktree .live/ inside this folder, which only "release" moves. The link works while this Mac is on.
#
#   sh share.sh            start (or restart) the app from .live/ and make sure the tunnel is up; prints the link
#   sh share.sh release    after a commit: test that commit in a scratch copy, move .live/ to it, restart only the app (the link stays)
#   sh share.sh status     what runs, which commit is live, whether newer commits wait for a release, the link
#   sh share.sh stop       stop the app and the tunnel
#   sh share.sh newlink    restart the tunnel as well (the link changes)
#
# The password is read from .streamlit/secrets.toml of this folder (made at random when the file does not exist) and is
# handed to the app as TP_PASSWORD; it is never printed. Change it by editing that file, then run: sh share.sh
# For a trial that must not touch the running site: TP_PORT=8789 TP_NO_TUNNEL=1 sh share.sh   (and the same with stop)

HERE=$(cd "$(dirname "$0")" && pwd) || exit 1
case "$HERE" in */.live|*/.live_next) HERE=$(dirname "$HERE") ;; esac      # the script also exists inside the pinned copy
cd "$HERE" || exit 1
PY="$HERE/.venv/bin/python"; [ -x "$PY" ] || PY=python3
SECRETS="$HERE/.streamlit/secrets.toml"
LIVE="$HERE/.live"
NEXT="$HERE/.live_next"
PORT="${TP_PORT:-8501}"
APP_PATTERN="streamlit run app.py --server.port $PORT "
LOG="$HERE/app.log"; [ "$PORT" = "8501" ] || LOG="$HERE/app_$PORT.log"      # a trial on another port keeps its own log
TUNNEL_PATTERN="cloudflared tunnel --url http://127.0.0.1:$PORT "

app_running()    { pgrep -f "$APP_PATTERN" >/dev/null 2>&1; }
tunnel_running() { pgrep -f "$TUNNEL_PATTERN" >/dev/null 2>&1; }
stop_app()       { for p in $(pgrep -f "$APP_PATTERN"); do kill "$p" 2>/dev/null; done; }
stop_tunnel()    { for p in $(pgrep -f "$TUNNEL_PATTERN"); do kill "$p" 2>/dev/null; done; }
healthy()        { curl -s -o /dev/null -m 3 "http://127.0.0.1:$PORT/_stcore/health"; }
is_repo()        { git -C "$HERE" rev-parse --git-dir >/dev/null 2>&1; }
live_commit()    { git -C "$LIVE" log --oneline -1 2>/dev/null | cut -c1-90; }

ensure_secrets() {
  if [ ! -f "$SECRETS" ]; then
    mkdir -p "$HERE/.streamlit"
    printf '[access]\npassword = "%s"\n' "$("$PY" -c 'import secrets; print(secrets.token_urlsafe(12))')" > "$SECRETS"
    chmod 600 "$SECRETS"
    echo "A new random password was written to $SECRETS"
  fi
}

password() { sed -n 's/^password *= *"\(.*\)" *$/\1/p' "$SECRETS" | head -1; }

ensure_live() {
  # The pinned copy that visitors see. Made at the newest commit when it does not exist yet.
  if [ -d "$LIVE" ]; then return 0; fi
  if ! is_repo; then
    echo "This folder is not a git repository, so there is no pinned copy; serving the working files themselves."
    LIVE="$HERE"; return 0
  fi
  git -C "$HERE" worktree prune >/dev/null 2>&1
  git -C "$HERE" worktree add --detach "$LIVE" HEAD >/dev/null 2>&1 || { echo "The pinned copy .live/ could not be made (git worktree add failed)."; exit 1; }
}

start_app() {
  PW=$(password)
  [ -n "$PW" ] || { echo "No password found in $SECRETS (expected a line: password = \"...\")."; exit 1; }
  stop_app; sleep 1
  # the public app must never start open: clear every switch that turns the sign-in off or pins one page
  ( cd "$LIVE" && exec env -u TP_OPEN -u PRAXIS_LAB_OPEN -u TP_PAGE -u PRAXIS_LAB_PAGE TP_PASSWORD="$PW" TP_CONTRIB_DIR="$HERE/contributions" nohup "$PY" -m streamlit run app.py \
      --server.port "$PORT" --server.address 127.0.0.1 --server.headless true ) > "$LOG" 2>&1 < /dev/null &
  for i in $(seq 1 40); do sleep 1; healthy && return 0; done
  echo "The app did not answer on port $PORT; see $LOG"; return 1
}

start_tunnel() {
  command -v cloudflared >/dev/null 2>&1 || { echo "cloudflared is not installed. Install once with: brew install cloudflared"; exit 1; }
  stop_tunnel; sleep 1
  nohup cloudflared tunnel --url "http://127.0.0.1:$PORT" --no-autoupdate > "$HERE/tunnel.log" 2>&1 < /dev/null &
  URL=""
  for i in $(seq 1 40); do
    sleep 1
    URL=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' "$HERE/tunnel.log" | head -1)
    [ -n "$URL" ] && break
  done
  [ -z "$URL" ] && { echo "no link yet; see tunnel.log"; exit 1; }
  echo "$URL" > "$HERE/tunnel.url"
}

write_note() {
  # The one place that holds the link and the password together. It stays on this Mac (it is in .gitignore).
  URL=$(cat "$HERE/tunnel.url" 2>/dev/null)
  {
    echo "ThreatPrint access (give the link and the password to the people who may use the site)"
    echo ""
    echo "Link:      $URL"
    echo "Password:  $(password)"
    echo ""
    echo "Where the password lives: $SECRETS  (this note is only a copy, rewritten by share.sh)."
    echo "Who chose it: nobody; share.sh made it at random when the site went up and no password existed. Change it by editing that file, then run: sh share.sh"
    echo "The link works while this Mac is on. It changes only when the tunnel restarts (sh share.sh newlink, or after a reboot)."
    echo "Live code: $(live_commit)"
    echo "Written: $(date '+%Y-%m-%d %H:%M')"
  } > "$HERE/ACCESS_PASSWORD.txt"
  chmod 600 "$HERE/ACCESS_PASSWORD.txt"
}

report() {
  echo ""
  echo "ThreatPrint link:  $(cat "$HERE/tunnel.url" 2>/dev/null)"
  echo "Password:          in $SECRETS (also copied to ACCESS_PASSWORD.txt, which stays on this Mac)"
  echo "Local address:     http://127.0.0.1:$PORT"
  echo "Live code:         $(live_commit)"
  echo ""
  echo "The link works while this Mac is on. Stop with: sh share.sh stop"
}

case "$1" in
  stop)
    stop_app
    [ -n "$TP_NO_TUNNEL" ] || stop_tunnel
    echo "stopped"; exit 0 ;;

  status)
    app_running && echo "app: running on port $PORT" || echo "app: not running on port $PORT"
    tunnel_running && echo "tunnel: running, link $(cat "$HERE/tunnel.url" 2>/dev/null)" || echo "tunnel: not running"
    if [ -d "$LIVE" ]; then
      echo "live code (.live): $(live_commit)"
      if is_repo; then
        HEAD_C=$(git -C "$HERE" rev-parse HEAD 2>/dev/null); LIVE_C=$(git -C "$LIVE" rev-parse HEAD 2>/dev/null)
        if [ "$HEAD_C" = "$LIVE_C" ]; then echo "the newest commit is live"
        else echo "newest commit:     $(git -C "$HERE" log --oneline -1 | cut -c1-90)"
             echo "$(git -C "$HERE" rev-list --count "$LIVE_C..$HEAD_C" 2>/dev/null) commit(s) wait for: sh share.sh release"; fi
        [ -n "$(git -C "$HERE" status --porcelain)" ] && echo "the working folder has changes that are not committed (visitors do not see them)"
      fi
    else
      echo "live code: no pinned copy yet (sh share.sh makes it)"
    fi
    exit 0 ;;

  release)
    is_repo || { echo "Not released: this folder is not a git repository."; exit 1; }
    if [ -n "$(git -C "$HERE" status --porcelain)" ]; then
      echo "Not released: the working folder has changes that are not committed. Commit them, then release (git status shows which)."; exit 1
    fi
    WANT=$(sed -n 's/^streamlit==\(.*\)$/\1/p' "$HERE/requirements-mac.txt" 2>/dev/null | head -1)
    HAVE=$("$PY" -c 'import streamlit; print(streamlit.__version__)' 2>/dev/null)
    if [ -n "$WANT" ] && [ "$WANT" != "$HAVE" ]; then
      echo "Not released: this commit wants streamlit $WANT and the install has ${HAVE:-none}. Update the install, then release:"
      echo "  $HERE/.venv/bin/pip install -r requirements-mac.txt"; exit 1
    fi
    ensure_secrets; ensure_live
    # Test the commit in a scratch copy, so that visitors never see code that failed its tests.
    git -C "$HERE" worktree remove --force "$NEXT" >/dev/null 2>&1; git -C "$HERE" worktree prune >/dev/null 2>&1
    git -C "$HERE" worktree add --detach "$NEXT" HEAD >/dev/null 2>&1 || { echo "Not released: the scratch copy could not be made."; exit 1; }
    echo "Testing $(git -C "$NEXT" log --oneline -1 | cut -c1-70) ..."
    if ( cd "$NEXT" && env -u TP_PASSWORD -u TP_OPEN -u TP_PAGE "$PY" -m pytest tests/test_app.py -q -p no:cacheprovider > "$HERE/release_tests.log" 2>&1 ); then
      tail -1 "$HERE/release_tests.log"
    else
      tail -15 "$HERE/release_tests.log"
      git -C "$HERE" worktree remove --force "$NEXT" >/dev/null 2>&1
      echo "Not released: the tests failed on this commit (release_tests.log). Visitors still see: $(live_commit)"; exit 1
    fi
    git -C "$HERE" worktree remove --force "$NEXT" >/dev/null 2>&1
    git -C "$LIVE" checkout --detach -q "$(git -C "$HERE" rev-parse HEAD)" || { echo "Not released: .live/ could not be moved to the new commit."; exit 1; }
    start_app || exit 1
    if [ -z "$TP_NO_TUNNEL" ]; then tunnel_running && [ -s "$HERE/tunnel.url" ] || start_tunnel; write_note; fi
    echo "Released. Visitors now see: $(live_commit)"
    [ -n "$TP_NO_TUNNEL" ] || report
    exit 0 ;;

  ""|start|newlink)
    ensure_secrets; ensure_live
    start_app || exit 1
    if [ -z "$TP_NO_TUNNEL" ]; then
      if [ "$1" = "newlink" ] || ! tunnel_running || [ ! -s "$HERE/tunnel.url" ]; then start_tunnel; fi      # an existing tunnel is kept, so the link stays
      write_note; report
    else
      echo "app on http://127.0.0.1:$PORT from $(live_commit) (no tunnel, by TP_NO_TUNNEL)"
    fi
    exit 0 ;;

  *)
    echo "usage: sh share.sh [start | release | status | stop | newlink]"; exit 1 ;;
esac
