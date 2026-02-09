#!/usr/bin/env bash
set -euo pipefail

WORKDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$WORKDIR/autosecure.sh"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

assert_eq() {
  local expected="$1"
  local got="$2"
  local name="$3"
  if [ "$expected" != "$got" ]; then
    printf 'FAIL: %s\nExpected:\n%s\nGot:\n%s\n' "$name" "$expected" "$got"
    exit 1
  fi
  printf 'PASS: %s\n' "$name"
}

cat > "$tmpdir/static.txt" <<'DATA'
# comment
; semi-comment

1.2.3.4 note
5.6.7.8
1.2.3.4 duplicate
DATA

cat > "$tmpdir/dshield.txt" <<'DATA'
# header
1.2.3.0 x 24
9.9.9.0 y 24
1.2.3.0 z 24
bad line
DATA

static_got="$(_parse_static_blocklist_file "$tmpdir/static.txt")"
static_expected=$'1.2.3.4\n5.6.7.8'
assert_eq "$static_expected" "$static_got" "static blocklist parsing"

dshield_got="$(_parse_dshield_file "$tmpdir/dshield.txt")"
dshield_expected=$'1.2.3.0/24\n9.9.9.0/24'
assert_eq "$dshield_expected" "$dshield_got" "dshield range parsing"

printf 'All tests passed.\n'
