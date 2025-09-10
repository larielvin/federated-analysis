#!/usr/bin/env bash
set -euo pipefail

# NAMES=(alice bob carol dave)
if [[ $# -lt 1 ]]; then
  echo "Usage: $0 user1 user2 user3..." >&2
  exit 1
fi
NAMES=("$@")

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGE_DIR="${AGE_DIR:-$SCRIPT_DIR/age_files/.secrets}"
OUT_DIR="${OUT_DIR:-$SCRIPT_DIR/age_files/recipients}"
RECIP_JSON="$OUT_DIR/recipients.json"
ENV_FILE="$OUT_DIR/recipients.env"

command -v age-keygen >/dev/null 2>&1 || {
  echo "ERROR: 'age-keygen' not found. Install 'age' first." >&2
  exit 1
}

file_hash() {
  local f="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$f" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    # macOS prints: "SHA256(file)= <hash>"
    openssl dgst -sha256 "$f" | awk '{print $2}'
  elif command -v python3 >/dev/null 2>&1; then
    python3 - "$f" <<'PY'
import sys, hashlib, pathlib
p = pathlib.Path(sys.argv[1])
print(hashlib.sha256(p.read_bytes()).hexdigest())
PY
  else
    echo "ERROR: need a sha256 tool (sha256sum/shasum/openssl/python3)" >&2
    return 1
  fi
}

mkdir -p "$AGE_DIR" "$OUT_DIR"
umask 077  # private files by default

declare -a JSON_ITEMS=()
declare -A SEEN_KEYS=()

for user in "${NAMES[@]}"; do
  id_path="$AGE_DIR/${user}.key"
  pub_path="$OUT_DIR/${user}.age.pub"

  if [[ ! -f "$id_path" ]]; then
    echo "Generating key for $user ..."
    age-keygen -o "$id_path" >/dev/null
  else
    echo "Using existing key for $user"
  fi

  # Export public key (strip newline)
  pub_key="$(age-keygen -y "$id_path" | tr -d '\r\n')"

  # quick sanity check 
  if [[ ! "$pub_key" =~ ^age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l0-9]+$ ]]; then
    echo "ERROR: Generated key for '$user' doesn't look like an age public key: $pub_key" >&2
    exit 1
  fi
  if [[ -n "${SEEN_KEYS[$pub_key]:-}" ]]; then
    echo "ERROR: Duplicate age public key generated (collision) for '$user'." >&2
    exit 1
  fi
  SEEN_KEYS[$pub_key]=1

  # Save per-user public key file
  printf '%s\n' "$pub_key" > "$pub_path"

  JSON_ITEMS+=("{\"id\":\"$user\",\"age_pubkey\":\"$pub_key\"}")
done

tmp_json="$(mktemp "$OUT_DIR/.recipients.json.tmp.XXXXXX")"
{
  echo '{'
  echo '  "schema": "recipients-v1",'
  echo '  "recipients": ['
  for i in "${!JSON_ITEMS[@]}"; do
    sep=','; (( i == ${#JSON_ITEMS[@]}-1 )) && sep=''
    printf '    %s%s\n' "${JSON_ITEMS[$i]}" "$sep"
  done
  echo '  ]'
  echo '}'
} > "$tmp_json"
mv -f "$tmp_json" "$RECIP_JSON"

RECIPIENTS_JSON_SHA256="$(file_hash "$RECIP_JSON")"
export RECIPIENTS_JSON_SHA256
printf 'RECIPIENTS_JSON_SHA256=%s\n' "$RECIPIENTS_JSON_SHA256" > "$ENV_FILE"

echo
echo "All set!"
echo "• Private keys:            $AGE_DIR/<user>.key"
echo "• Public keys:             $OUT_DIR/<user>.age.pub"
echo "• JSON policy:             $RECIP_JSON"
echo "• SHA256(recipients.json): $RECIPIENTS_JSON_SHA256"
echo "• Env file:                $ENV_FILE"
