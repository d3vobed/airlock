#!/usr/bin/env bash
# Launch the AIRLOCK live stack: gateway + public Cloudflare tunnel.
#
# The Vercel-hosted UI (frontend-theta-six-65.vercel.app) points its
# NEXT_PUBLIC_API_BASE at the tunnel URL. If the tunnel URL changes after a
# restart, update the Vercel project env and push an empty commit to main:
#
#   vercel env rm NEXT_PUBLIC_API_BASE production --yes
#   vercel env add NEXT_PUBLIC_API_BASE production   # paste the URL below
#   git commit --allow-empty -m "ci: refresh gateway endpoint"
#   git push origin main
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UA="uvicorn apps.gateway.main:app --host 0.0.0.0 --port 8000"
CLOUDFLARED=${CLOUDFLARED:-/tmp/cloudflared}

[ -x "$ROOT/.venv/bin/uvicorn" ] || { echo "create venv: make setup"; exit 1; }
[ -x "$CLOUDFLARED" ] || { echo "cloudflared missing at $CLOUDFLARED"; exit 1; }

if ! curl -sf --max-time 2 http://localhost:8000/health > /dev/null 2>&1; then
  echo "[gateway] starting on :8000 (CORS *)"
  AIRLOCK_CORS_ORIGINS='*' setsid "$ROOT/.venv/bin/uvicorn" "$UA" \
    >> /tmp/gateway.log 2>&1 < /dev/null &
  sleep 3
fi
curl -sf --max-time 5 http://localhost:8000/health > /dev/null && echo "[gateway] online"

if ! pgrep -f "cloudflared tunnel --no-autoupdate" > /dev/null 2>&1; then
  echo "[tunnel] starting"
  setsid "$CLOUDFLARED" tunnel --no-autoupdate --url http://localhost:8000 \
    > /tmp/cloudflared.log 2>&1 < /dev/null &
fi
for _ in $(seq 1 30); do
  URL=$(grep -oE "https://[-a-zA-Z0-9]+\.trycloudflare\.com" /tmp/cloudflared.log | head -1)
  [ -n "$URL" ] && break
  sleep 2
done
[ -n "${URL:-}" ] || { echo "tunnel failed; see /tmp/cloudflared.log"; exit 1; }
echo "[tunnel] public URL: $URL"
curl -sf --max-time 15 "$URL/health" && echo && echo "[live] UI: https://frontend-theta-six-65.vercel.app"