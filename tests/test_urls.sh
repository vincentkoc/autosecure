#!/usr/bin/env bash
set -euo pipefail

URLS=(
  "https://www.spamhaus.org/drop/drop.txt"
  "https://www.spamhaus.org/drop/edrop.txt"
  "http://feeds.dshield.org/block.txt"
  # Disabled: ZeusTracker endpoint is no longer available.
  # "https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist"
)

get_http_code() {
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -sS -L --max-time 30 -o /dev/null -w "%{http_code}" "$url"
    return 0
  fi

  if command -v wget >/dev/null 2>&1; then
    wget -q --spider --server-response "$url" 2>&1 | awk '/^  HTTP\// { code=$2 } END { print code }'
    return 0
  fi

  echo "000"
}

for url in "${URLS[@]}"; do
  code="$(get_http_code "$url")"
  if [ "$code" != "200" ]; then
    printf "FAIL: %s returned HTTP %s\n" "$url" "$code"
    exit 1
  fi
  printf "PASS: %s returned HTTP 200\n" "$url"
done

printf "All URL checks passed.\n"
