#!/bin/sh
# Put Praxis Lab on a public https link with a password (Cloudflare quick tunnel, no account needed).
# The link works only while this Mac is on and this script's processes are running.
#   sh share.sh            start the app with the password and open the link (prints the link; password is in .streamlit/secrets.toml)
#   sh share.sh stop       stop the app and the tunnel
#   sh share.sh status     show whether they run and the current link
cd "$(dirname "$0")" || exit 1
PY=".venv/bin/python"; [ -x "$PY" ] || PY=python3
SECRETS=".streamlit/secrets.toml"
if [ "$1" = "stop" ]; then
  for p in $(pgrep -f 'streamlit run app.py'); do kill "$p" 2>/dev/null; done
  for p in $(pgrep -f 'cloudflared tunnel'); do kill "$p" 2>/dev/null; done
  echo "stopped"; exit 0
fi
if [ "$1" = "status" ]; then
  pgrep -f 'streamlit run app.py' >/dev/null && echo "app: running" || echo "app: not running"
  pgrep -f 'cloudflared tunnel' >/dev/null && echo "tunnel: running, link $(cat tunnel.url 2>/dev/null)" || echo "tunnel: not running"
  exit 0
fi
command -v cloudflared >/dev/null 2>&1 || { echo "cloudflared is not installed. Install once with: brew install cloudflared"; exit 1; }
if [ ! -f "$SECRETS" ]; then
  mkdir -p .streamlit
  printf '[access]\npassword = "%s"\n' "$($PY -c 'import secrets; print(secrets.token_urlsafe(12))')" > "$SECRETS"
  chmod 600 "$SECRETS"
fi
for p in $(pgrep -f 'streamlit run app.py'); do kill "$p" 2>/dev/null; done
for p in $(pgrep -f 'cloudflared tunnel'); do kill "$p" 2>/dev/null; done
sleep 1
nohup "$PY" -m streamlit run app.py --server.port 8501 --server.address 127.0.0.1 --server.headless true > app.log 2>&1 &
nohup cloudflared tunnel --url http://127.0.0.1:8501 --no-autoupdate > tunnel.log 2>&1 &
URL=""
for i in $(seq 1 40); do
  sleep 1
  URL=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' tunnel.log | head -1)
  [ -n "$URL" ] && break
done
[ -z "$URL" ] && { echo "no link yet; see tunnel.log"; exit 1; }
echo "$URL" > tunnel.url
echo ""
echo "Praxis Lab link:   $URL"
echo "Password:          in $SECRETS (open it to read or change it; restart with sh share.sh after a change)"
echo "Local address:     http://127.0.0.1:8501"
echo ""
echo "The link works while this Mac is on and these processes run. Stop with: sh share.sh stop"
