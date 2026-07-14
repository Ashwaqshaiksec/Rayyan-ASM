#!/usr/bin/env bash
# rotate-credential-key.sh — safely rotate RAYYAN_AUTH_CREDENTIALKEY
# Usage: ./scripts/rotate-credential-key.sh <API_BASE_URL> <ADMIN_TOKEN> <NEW_KEY>
#
# Steps performed:
#   1. Export all tool credentials (plaintext) using the old key
#   2. Prompt user to update RAYYAN_AUTH_CREDENTIALKEY and restart the app
#   3. Re-import credentials (encrypted with the new key)

set -euo pipefail

API="${1:-}"
TOKEN="${2:-}"
NEW_KEY="${3:-}"

if [[ -z "$API" || -z "$TOKEN" || -z "$NEW_KEY" ]]; then
  echo "Usage: $0 <API_BASE_URL> <ADMIN_TOKEN> <NEW_BASE64_KEY>"
  echo "Example: $0 https://asm.example.com Bearer_token_here \$(openssl rand -base64 32)"
  exit 1
fi

# Use a locked-down temp directory — credentials must never land in world-readable /tmp
SECURE_TMP=$(mktemp -d)
chmod 700 "$SECURE_TMP"
trap 'rm -rf "$SECURE_TMP"' EXIT
EXPORT_FILE="$SECURE_TMP/rayyan-creds-export.json"

echo "[1/4] Exporting credentials from $API ..."
curl -sf -H "Authorization: Bearer $TOKEN" \
  "$API/api/v1/tool-credentials?limit=500" \
  -o "$EXPORT_FILE"

COUNT=$(python3 -c "import json,sys; d=json.load(open('$EXPORT_FILE')); print(len(d.get('data',[])))")
echo "      Exported $COUNT credentials to $EXPORT_FILE"

echo ""
echo "[2/4] Update RAYYAN_AUTH_CREDENTIALKEY to your new key and restart the app."
echo "      New key: $NEW_KEY"
echo ""
read -rp "      Press ENTER once the app is restarted with the new key ... "

echo ""
echo "[3/4] Re-importing $COUNT credentials with the new key ..."
python3 - "$EXPORT_FILE" "$API" "$TOKEN" << 'PYEOF'
import json, sys, urllib.request, urllib.error

export_file, api, token = sys.argv[1], sys.argv[2], sys.argv[3]

with open(export_file) as f:
    creds = json.load(f).get('data', [])

ok, fail = 0, 0
for c in creds:
    payload = json.dumps({
        'name': c['name'],
        'tool': c['tool'],
        'credential_type': c['credential_type'],
        'value': c['value'],
    }).encode()
    req = urllib.request.Request(
        f"{api}/api/v1/tool-credentials",
        data=payload,
        headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        urllib.request.urlopen(req)
        ok += 1
    except urllib.error.HTTPError as e:
        print(f"  FAIL {c['name']}: {e.code} {e.read().decode()[:80]}")
        fail += 1

print(f"  Re-imported: {ok} ok, {fail} failed")
PYEOF

echo ""
echo "[4/4] Cleanup"
echo "      Secure temp directory removed by trap handler."
echo ""
echo "IMPORTANT: Revoke the old key from any external secret manager or .env backups."
