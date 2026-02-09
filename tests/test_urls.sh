#!/usr/bin/env bash
set -euo pipefail

if [ "${AUTOSECURE_SKIP_NETWORK_TESTS:-0}" = "1" ]; then
  echo "Skipping network URL checks (AUTOSECURE_SKIP_NETWORK_TESTS=1)."
  exit 0
fi

URLS=(
  "https://www.spamhaus.org/drop/drop.txt"
  "https://www.spamhaus.org/drop/edrop.txt"
  "https://feeds.dshield.org/block.txt"
  "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
  "https://reputation.alienvault.com/reputation.data"
  # Disabled: ZeusTracker endpoint is no longer available.
  # "https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist"
)

get_http_code() {
  local url="$1"
  local attempt
  local code=""

  for attempt in 1 2 3; do
    if command -v curl >/dev/null 2>&1; then
      code="$(curl -sS -L --max-time 30 -o /dev/null -w "%{http_code}" "$url" || true)"
    elif command -v wget >/dev/null 2>&1; then
      code="$(wget -q --spider --server-response "$url" 2>&1 | awk '/^  HTTP\// { c=$2 } END { print c }')"
    else
      code="000"
    fi

    if [ "$code" = "200" ]; then
      echo "$code"
      return 0
    fi

    # transient network failures are common in CI; retry a few times
    echo "Attempt ${attempt}/3 for ${url} returned ${code:-000}, retrying..."
    sleep 2
  done

  echo "${code:-000}"
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
