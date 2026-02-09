#!/usr/bin/env bash

set -euo pipefail

# Automatic pulling of spam lists to block IP's
# Copyright (C) 2013 David @cowgill
# Copyright (C) 2014 Vincent Koc @koconder
# Copyright (C) 2014 Volkan @volkan-k
# Copyright (C) 2016 Anasxrt @Anasxrt

# based off the following two scripts
# http://www.theunsupported.com/2012/07/block-malicious-ip-addresses/
# http://www.cyberciti.biz/tips/block-spamming-scanning-with-iptables.html

# Runtime defaults
QUIET=0
LOG_FILE="/var/log/autosecure.log"
TMP_DIR="/tmp/autosecure"
DOWNLOADER=""
IPTABLES=""

# logger from @phracker
_log () {
    if [ "$QUIET" -eq 0 ] ; then
        printf "%s: %s\n" "$(date "+%Y-%m-%d %H:%M:%S.%N")" "$*" | tee -a "$LOG_FILE"
    fi
}

_die () {
    _log "ERROR: $*"
    exit 1
}

_require_cmd () {
    if ! command -v "$1" >/dev/null 2>&1; then
        _die "Required command not found: $1"
    fi
}

_download_file () {
    local url="$1"
    local output="$2"

    if [ "$DOWNLOADER" = "wget" ]; then
        wget -q -O "$output" "$url"
    else
        curl -fsSL "$url" -o "$output"
    fi
}

_ensure_chain () {
    if "$IPTABLES" -L "$1" -n >/dev/null 2>&1; then
        "$IPTABLES" -F "$1" >/dev/null 2>&1
    else
        "$IPTABLES" -N "$1" >/dev/null 2>&1
    fi
}

_ensure_jump () {
    local from_chain="$1"
    local to_chain="$2"
    if ! "$IPTABLES" -C "$from_chain" -j "$to_chain" >/dev/null 2>&1; then
        "$IPTABLES" -A "$from_chain" -j "$to_chain" >/dev/null 2>&1
    fi
}

_add_block_rules () {
    local ip="$1"
    "$IPTABLES" -A "$CHAIN" -s "$ip" -j "$CHAINACT"
    if [ "$EGF" -ne 0 ]; then
        "$IPTABLES" -A "$CHAIN" -d "$ip" -j "$CHAINACT"
    fi
}

_select_downloader () {
    if command -v wget >/dev/null 2>&1; then
        DOWNLOADER="wget"
    elif command -v curl >/dev/null 2>&1; then
        DOWNLOADER="curl"
    else
        _die "Required downloader not found: install wget or curl."
    fi
}

_parse_dshield_file () {
    local file="$1"
    awk '/^[0-9]/ { print $1 "/" $3 }' "$file" | sort -u
}

_parse_static_blocklist_file () {
    local file="$1"
    grep -E -v '^(;|#|$)' "$file" | awk '{ print $1 }' | sort -u
}

main () {
    # Quiet run for cron usage from @ShamimIslam/spamhaus
    if [ "${1:-}" = "-q" ]; then
        QUIET=1
        shift
    fi

    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        _die "This script must run as root."
    fi

    _require_cmd iptables
    _require_cmd awk
    _require_cmd grep
    _require_cmd sort
    _require_cmd mkdir
    _select_downloader

    IPTABLES="$(command -v iptables)"

    # list of known spammers
    # Dsheild based on earlier work from:
    # http://wiki.brokenpoet.org/wiki/Get_DShield_Blocklist
    # https://github.com/koconder/dshield_automatic_iptables
    URLS=(
        "https://www.spamhaus.org/drop/drop.txt"
        "https://www.spamhaus.org/drop/edrop.txt"
        "http://feeds.dshield.org/block.txt"
        # Disabled: ZeusTracker endpoint is no longer available.
        # "https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist"
    )

    # save local copy here
    FILES=(
        "${TMP_DIR}/spamhaus_drop.txt"
        "${TMP_DIR}/spamhaus_edrop.txt"
        "${TMP_DIR}/dshield_drop.txt"
        # "${TMP_DIR}/abusech_drop.txt"
    )

    # iptables custom chain for Bad IPs
    CHAIN="Autosecure"
    # iptables custom chain for actions
    CHAINACT="AutosecureAct"

    # Outbound (egress) filtering is not required but makes your Autosecure setup
    # complete by providing full inbound and outbound packet filtering. You can
    # toggle outbound filtering on or off with the EGF variable.
    # It is strongly recommended that this option NOT be disabled.
    EGF="1"

    mkdir -p "$TMP_DIR"

    if "$IPTABLES" -L "$CHAIN" -n >/dev/null 2>&1; then
        _log "Flushed old rules. Applying updated Autosecure list..."
    else
        _log "Chain not detected. Creating new chain and adding Autoblock list..."
    fi

    _ensure_chain "$CHAIN"
    _ensure_chain "$CHAINACT"

    # tie chain to base chains only once
    _ensure_jump INPUT "$CHAIN"
    _ensure_jump FORWARD "$CHAIN"
    if [ "$EGF" -ne 0 ]; then
        _ensure_jump OUTPUT "$CHAIN"
    fi

    # add the ip address log rule to the action chain
    "$IPTABLES" -A "$CHAINACT" -j LOG --log-prefix "[AUTOSECURE BLOCK] " -m limit --limit 3/min --limit-burst 10 >/dev/null 2>&1

    # add the ip address drop rule to the action chain
    "$IPTABLES" -A "$CHAINACT" -j DROP >/dev/null 2>&1

    for idx in "${!URLS[@]}"; do
        URL="${URLS[$idx]}"
        FILE="${FILES[$idx]}"

        # get a copy of the spam list
        _log "Downloading ${URL} to ${FILE} using ${DOWNLOADER}..."
        if ! _download_file "${URL}" "${FILE}"; then
            _log "Failed to download ${URL}. Skipping this source."
            continue
        fi

        if [ ! -s "${FILE}" ]; then
            _log "Downloaded file is empty: ${FILE}. Skipping."
            rm -f "${FILE}"
            continue
        fi

        # iterate through all known spamming hosts
        _log "Parsing hosts in ${FILE}..."

        # Check if we are testing for dSheild (Range), versus static IPs\
        # @credit: https://github.com/koconder/dshield_automatic_iptables
        if [ "${idx}" -eq 2 ]; then
            # Block an IP Range
            while IFS= read -r IP; do
                [ -n "${IP}" ] || continue
                _add_block_rules "${IP}"
                _log "IP: ${IP}"
            done < <(_parse_dshield_file "${FILE}")
        else
            # Block a static IP
            while IFS= read -r IP; do
                [ -n "${IP}" ] || continue
                _add_block_rules "${IP}"
                _log "IP: ${IP}"
            done < <(_parse_static_blocklist_file "${FILE}")
        fi

        # remove the spam list
        _log "Done parsing ${FILE}. Removing..."
        rm -f "${FILE}"
    done

    _log "Completed."
}

if [[ "${BASH_SOURCE[0]}" = "$0" ]]; then
    main "$@"
fi
