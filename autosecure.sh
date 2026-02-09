#!/usr/bin/env bash

set -euo pipefail

# Automatic pulling of spam lists to block IP's
# Copyright (C) 2013 David @cowgill
# Copyright (C) 2014 Vincent Koc @koconder
# Copyright (C) 2014 Volkan @volkan-k
# Copyright (C) 2016 Anasxrt @Anasxrt

# Runtime defaults
QUIET=0
LOG_FILE="/var/log/autosecure.log"
TMP_DIR="/tmp/autosecure"
STATE_DIR="/var/lib/autosecure"
CACHE_FILE="${STATE_DIR}/blocked_ips.txt"
DOWNLOADER=""

# Firewall backend: auto|iptables|nft|pf
AUTOSECURE_FIREWALL_BACKEND="${AUTOSECURE_FIREWALL_BACKEND:-${FIREWALL_BACKEND:-auto}}"
FIREWALL_BACKEND="$AUTOSECURE_FIREWALL_BACKEND"

# iptables settings
IPTABLES_BIN=""
IP6TABLES_BIN=""
IPSET_BIN=""
XTABLES_WAIT="${XTABLES_WAIT:-5}"
AUTOSECURE_XTABLES_WAIT="${AUTOSECURE_XTABLES_WAIT:-${XTABLES_WAIT:-5}}"
XTABLES_WAIT="$AUTOSECURE_XTABLES_WAIT"
AUTOSECURE_RULE_POSITION="${AUTOSECURE_RULE_POSITION:-${RULE_POSITION:-append}}"
RULE_POSITION="$AUTOSECURE_RULE_POSITION"
AUTOSECURE_IPV6_ENABLE="${AUTOSECURE_IPV6_ENABLE:-${IPV6_ENABLE:-0}}"
IPV6_ENABLE="$AUTOSECURE_IPV6_ENABLE"
AUTOSECURE_IPSET_ENABLE="${AUTOSECURE_IPSET_ENABLE:-${IPSET_ENABLE:-0}}"
IPSET_ENABLE="$AUTOSECURE_IPSET_ENABLE"
AUTOSECURE_EGF="${AUTOSECURE_EGF:-${EGF:-1}}"
EGF="$AUTOSECURE_EGF"
CHAIN="Autosecure"
CHAINACT="AutosecureAct"
IPSET_V4_NAME="AutosecureV4"
IPSET_V6_NAME="AutosecureV6"

# nftables settings
NFT_BIN=""
NFT_TABLE="${NFT_TABLE:-autosecure}"

# pf (macOS) settings
PFCTL_BIN=""
PF_ANCHOR="${PF_ANCHOR:-autosecure}"
PF_ANCHOR_FILE="/etc/pf.anchors/${PF_ANCHOR}"

# Additional feeds (comma-separated)
# Example: AUTOSECURE_EXTRA_FEEDS="https://example.com/feed1.txt,https://example.com/feed2.txt"
AUTOSECURE_EXTRA_FEEDS="${AUTOSECURE_EXTRA_FEEDS:-${EXTRA_FEEDS:-}}"

_log() {
    if [ "$QUIET" -eq 0 ]; then
        printf "%s: %s\n" "$(date "+%Y-%m-%d %H:%M:%S.%N")" "$*" | tee -a "$LOG_FILE"
    fi
}

_die() {
    _log "ERROR: $*"
    exit 1
}

_require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        _die "Required command not found: $1"
    fi
}

_select_downloader() {
    if command -v wget >/dev/null 2>&1; then
        DOWNLOADER="wget"
    elif command -v curl >/dev/null 2>&1; then
        DOWNLOADER="curl"
    else
        _die "Required downloader not found: install wget or curl."
    fi
}

_download_file() {
    local url="$1"
    local output="$2"

    if [ "$DOWNLOADER" = "wget" ]; then
        wget -q -O "$output" "$url"
    else
        curl -fsSL "$url" -o "$output"
    fi
}

_parse_dshield_file() {
    local file="$1"
    awk '/^[0-9]/ { print $1 "/" $3 }' "$file" | sort -u
}

_parse_static_blocklist_file() {
    local file="$1"
    grep -E -v '^(;|#|$)' "$file" | awk '{ print $1 }' | sort -u
}

_is_valid_ip_or_cidr() {
    local ip="$1"

    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?$ ]]; then
        return 0
    fi

    if [[ "$ip" =~ ^[0-9A-Fa-f:]+(/([0-9]|[1-9][0-9]|1[01][0-9]|12[0-8]))?$ ]]; then
        return 0
    fi

    return 1
}

_ip_matches_family() {
    local family="$1"
    local ip="$2"

    if [ "$family" = "v4" ]; then
        [[ "$ip" != *:* ]]
    else
        [[ "$ip" == *:* ]]
    fi
}

_ipset_set_name() {
    local family="$1"
    if [ "$family" = "v4" ]; then
        printf '%s\n' "$IPSET_V4_NAME"
    else
        printf '%s\n' "$IPSET_V6_NAME"
    fi
}

_parse_extra_feeds() {
    if [ -z "$AUTOSECURE_EXTRA_FEEDS" ]; then
        return 0
    fi

    printf '%s\n' "$AUTOSECURE_EXTRA_FEEDS" | tr ',' '\n' | awk 'NF > 0 { print $0 }'
}

_detect_firewall_backend() {
    if [ "$FIREWALL_BACKEND" != "auto" ]; then
        return 0
    fi

    if [ "$(uname -s)" = "Darwin" ]; then
        FIREWALL_BACKEND="pf"
        return 0
    fi

    if command -v nft >/dev/null 2>&1; then
        FIREWALL_BACKEND="nft"
        return 0
    fi

    FIREWALL_BACKEND="iptables"
}

_validate_settings() {
    case "$RULE_POSITION" in
        append|top) ;;
        *) _die "RULE_POSITION must be 'append' or 'top' (got: ${RULE_POSITION})" ;;
    esac

    case "$IPV6_ENABLE" in
        0|1) ;;
        *) _die "IPV6_ENABLE must be 0 or 1 (got: ${IPV6_ENABLE})" ;;
    esac

    case "$IPSET_ENABLE" in
        0|1) ;;
        *) _die "IPSET_ENABLE must be 0 or 1 (got: ${IPSET_ENABLE})" ;;
    esac

    case "$EGF" in
        0|1) ;;
        *) _die "EGF must be 0 or 1 (got: ${EGF})" ;;
    esac

    case "$FIREWALL_BACKEND" in
        auto|iptables|nft|pf) ;;
        *) _die "FIREWALL_BACKEND must be auto|iptables|nft|pf (got: ${FIREWALL_BACKEND})" ;;
    esac

    if ! [[ "$XTABLES_WAIT" =~ ^[0-9]+$ ]]; then
        _die "XTABLES_WAIT must be an integer (got: ${XTABLES_WAIT})"
    fi
}

_collect_feed_data() {
    local output_file="$1"

    local urls=(
        "https://www.spamhaus.org/drop/drop.txt"
        "https://www.spamhaus.org/drop/edrop.txt"
        "http://feeds.dshield.org/block.txt"
    )

    local files=(
        "${TMP_DIR}/spamhaus_drop.txt"
        "${TMP_DIR}/spamhaus_edrop.txt"
        "${TMP_DIR}/dshield_drop.txt"
    )

    while IFS= read -r extra; do
        urls+=("$extra")
        files+=("${TMP_DIR}/extra_$(printf '%03d' "${#files[@]}").txt")
    done < <(_parse_extra_feeds)

    : > "$output_file"

    for idx in "${!urls[@]}"; do
        local url="${urls[$idx]}"
        local file="${files[$idx]}"

        _log "Downloading ${url} to ${file} using ${DOWNLOADER}..."
        if ! _download_file "$url" "$file"; then
            _log "Failed to download ${url}. Skipping this source."
            continue
        fi

        if [ ! -s "$file" ]; then
            _log "Downloaded file is empty: ${file}. Skipping."
            rm -f "$file"
            continue
        fi

        _log "Parsing hosts in ${file}..."

        # Index 2 is DShield format. All others are treated as static blocklist lines.
        if [ "$idx" -eq 2 ]; then
            while IFS= read -r ip; do
                [ -n "$ip" ] || continue
                if _is_valid_ip_or_cidr "$ip"; then
                    printf '%s\n' "$ip" >> "$output_file"
                fi
            done < <(_parse_dshield_file "$file")
        else
            while IFS= read -r ip; do
                [ -n "$ip" ] || continue
                if _is_valid_ip_or_cidr "$ip"; then
                    printf '%s\n' "$ip" >> "$output_file"
                fi
            done < <(_parse_static_blocklist_file "$file")
        fi

        _log "Done parsing ${file}. Removing..."
        rm -f "$file"
    done

    sort -u -o "$output_file" "$output_file"
}

_fw_cmd() {
    local family="$1"
    shift

    if [ "$family" = "v4" ]; then
        "$IPTABLES_BIN" -w "$XTABLES_WAIT" "$@"
    else
        "$IP6TABLES_BIN" -w "$XTABLES_WAIT" "$@"
    fi
}

_ipset_cmd() {
    "$IPSET_BIN" "$@"
}

_iptables_ensure_chain() {
    local family="$1"
    local chain="$2"

    if _fw_cmd "$family" -L "$chain" -n >/dev/null 2>&1; then
        _fw_cmd "$family" -F "$chain" >/dev/null 2>&1
    else
        _fw_cmd "$family" -N "$chain" >/dev/null 2>&1
    fi
}

_iptables_ensure_jump() {
    local family="$1"
    local from_chain="$2"
    local to_chain="$3"

    if ! _fw_cmd "$family" -C "$from_chain" -j "$to_chain" >/dev/null 2>&1; then
        if [ "$RULE_POSITION" = "top" ]; then
            _fw_cmd "$family" -I "$from_chain" -j "$to_chain" >/dev/null 2>&1
        else
            _fw_cmd "$family" -A "$from_chain" -j "$to_chain" >/dev/null 2>&1
        fi
    fi
}

_iptables_prepare_ipset() {
    local family="$1"
    local set_name
    set_name="$(_ipset_set_name "$family")"

    if [ "$family" = "v4" ]; then
        _ipset_cmd create "$set_name" hash:net family inet -exist
    else
        _ipset_cmd create "$set_name" hash:net family inet6 -exist
    fi
    _ipset_cmd flush "$set_name"
}

_iptables_prepare_chains() {
    local family="$1"

    _iptables_ensure_chain "$family" "$CHAIN"
    _iptables_ensure_chain "$family" "$CHAINACT"

    _iptables_ensure_jump "$family" INPUT "$CHAIN"
    _iptables_ensure_jump "$family" FORWARD "$CHAIN"
    if [ "$EGF" -ne 0 ]; then
        _iptables_ensure_jump "$family" OUTPUT "$CHAIN"
    fi

    _fw_cmd "$family" -A "$CHAINACT" -j LOG --log-prefix "[AUTOSECURE BLOCK] " -m limit --limit 3/min --limit-burst 10 >/dev/null 2>&1
    _fw_cmd "$family" -A "$CHAINACT" -j DROP >/dev/null 2>&1

    if [ "$IPSET_ENABLE" -eq 1 ]; then
        _iptables_prepare_ipset "$family"
        local set_name
        set_name="$(_ipset_set_name "$family")"
        _fw_cmd "$family" -A "$CHAIN" -m set --match-set "$set_name" src -j "$CHAINACT"
        if [ "$EGF" -ne 0 ]; then
            _fw_cmd "$family" -A "$CHAIN" -m set --match-set "$set_name" dst -j "$CHAINACT"
        fi
    fi
}

_iptables_apply_list_family() {
    local family="$1"
    local list_file="$2"
    local count=0

    _iptables_prepare_chains "$family"

    while IFS= read -r ip; do
        [ -n "$ip" ] || continue
        if ! _ip_matches_family "$family" "$ip"; then
            continue
        fi

        if [ "$IPSET_ENABLE" -eq 1 ]; then
            _ipset_cmd add "$(_ipset_set_name "$family")" "$ip" -exist
        else
            _fw_cmd "$family" -A "$CHAIN" -s "$ip" -j "$CHAINACT"
            if [ "$EGF" -ne 0 ]; then
                _fw_cmd "$family" -A "$CHAIN" -d "$ip" -j "$CHAINACT"
            fi
        fi
        count=$((count + 1))
    done < "$list_file"

    _log "[iptables/${family}] Applied ${count} block entries."
}

_apply_with_iptables() {
    local list_file="$1"

    _iptables_apply_list_family v4 "$list_file"
    if [ "$IPV6_ENABLE" -eq 1 ]; then
        _iptables_apply_list_family v6 "$list_file"
    fi
}

_apply_with_nft() {
    local list_file="$1"
    local v4_elements=""
    local v6_elements=""
    local first_v4=1
    local first_v6=1

    while IFS= read -r ip; do
        [ -n "$ip" ] || continue
        if _ip_matches_family v4 "$ip"; then
            if [ "$first_v4" -eq 1 ]; then
                v4_elements="$ip"
                first_v4=0
            else
                v4_elements="${v4_elements}, ${ip}"
            fi
        else
            if [ "$first_v6" -eq 1 ]; then
                v6_elements="$ip"
                first_v6=0
            else
                v6_elements="${v6_elements}, ${ip}"
            fi
        fi
    done < "$list_file"

    local output_rules="${TMP_DIR}/autosecure.nft"

    {
        echo "flush table inet ${NFT_TABLE}"
        echo "table inet ${NFT_TABLE} {"
        echo "  set bad_ipv4 {"
        echo "    type ipv4_addr"
        echo "    flags interval"
        if [ -n "$v4_elements" ]; then
            echo "    elements = { ${v4_elements} }"
        fi
        echo "  }"
        echo "  set bad_ipv6 {"
        echo "    type ipv6_addr"
        echo "    flags interval"
        if [ -n "$v6_elements" ]; then
            echo "    elements = { ${v6_elements} }"
        fi
        echo "  }"

        echo "  chain input {"
        echo "    type filter hook input priority 0; policy accept;"
        echo "    ip saddr @bad_ipv4 log prefix \"[AUTOSECURE BLOCK] \" limit rate 3/minute drop"
        if [ "$IPV6_ENABLE" -eq 1 ]; then
            echo "    ip6 saddr @bad_ipv6 log prefix \"[AUTOSECURE BLOCK] \" limit rate 3/minute drop"
        fi
        echo "  }"

        echo "  chain forward {"
        echo "    type filter hook forward priority 0; policy accept;"
        echo "    ip saddr @bad_ipv4 log prefix \"[AUTOSECURE BLOCK] \" limit rate 3/minute drop"
        if [ "$IPV6_ENABLE" -eq 1 ]; then
            echo "    ip6 saddr @bad_ipv6 log prefix \"[AUTOSECURE BLOCK] \" limit rate 3/minute drop"
        fi
        echo "  }"

        if [ "$EGF" -ne 0 ]; then
            echo "  chain output {"
            echo "    type filter hook output priority 0; policy accept;"
            echo "    ip daddr @bad_ipv4 log prefix \"[AUTOSECURE BLOCK] \" limit rate 3/minute drop"
            if [ "$IPV6_ENABLE" -eq 1 ]; then
                echo "    ip6 daddr @bad_ipv6 log prefix \"[AUTOSECURE BLOCK] \" limit rate 3/minute drop"
            fi
            echo "  }"
        fi
        echo "}"
    } > "$output_rules"

    "$NFT_BIN" -f "$output_rules"
    _log "[nft] Applied nftables table '${NFT_TABLE}'."
}

_pf_bootstrap_anchor() {
    local anchor_line="anchor \"${PF_ANCHOR}\""
    local load_line="load anchor \"${PF_ANCHOR}\" from \"${PF_ANCHOR_FILE}\""

    touch "$PF_ANCHOR_FILE"

    if ! grep -qF "$anchor_line" /etc/pf.conf; then
        printf '%s\n' "$anchor_line" >> /etc/pf.conf
        _log "[pf] Added anchor line to /etc/pf.conf."
    fi

    if ! grep -qF "$load_line" /etc/pf.conf; then
        printf '%s\n' "$load_line" >> /etc/pf.conf
        _log "[pf] Added load anchor line to /etc/pf.conf."
    fi

    if ! "$PFCTL_BIN" -nf /etc/pf.conf >/dev/null 2>&1; then
        _die "Failed to validate /etc/pf.conf after pf bootstrap."
    fi

    "$PFCTL_BIN" -f /etc/pf.conf >/dev/null 2>&1
}

_apply_with_pf() {
    local list_file="$1"

    if [ "$(uname -s)" != "Darwin" ]; then
        _die "pf backend is intended for macOS/Darwin."
    fi

    _pf_bootstrap_anchor

    cat > "$PF_ANCHOR_FILE" <<PFEOF
# Managed by autosecure
# See /etc/pf.conf for anchor inclusion.
table <autosecure_bad_hosts> persist
block in quick from <autosecure_bad_hosts> to any
PFEOF

    if [ "$EGF" -ne 0 ]; then
        cat >> "$PF_ANCHOR_FILE" <<PFEOF
block out quick from any to <autosecure_bad_hosts>
PFEOF
    fi

    "$PFCTL_BIN" -a "$PF_ANCHOR" -f "$PF_ANCHOR_FILE"
    "$PFCTL_BIN" -a "$PF_ANCHOR" -t autosecure_bad_hosts -T replace -f "$list_file"
    "$PFCTL_BIN" -e >/dev/null 2>&1 || true

    _log "[pf] Applied anchor '${PF_ANCHOR}'."
}

main() {
    if [ "${1:-}" = "-q" ]; then
        QUIET=1
        shift
    fi

    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        _die "This script must run as root."
    fi

    _validate_settings
    _select_downloader
    _require_cmd awk
    _require_cmd grep
    _require_cmd sort
    _require_cmd mkdir

    _detect_firewall_backend

    case "$FIREWALL_BACKEND" in
        iptables)
            _require_cmd iptables
            IPTABLES_BIN="$(command -v iptables)"
            if [ "$IPV6_ENABLE" -eq 1 ]; then
                _require_cmd ip6tables
                IP6TABLES_BIN="$(command -v ip6tables)"
            fi
            if [ "$IPSET_ENABLE" -eq 1 ]; then
                _require_cmd ipset
                IPSET_BIN="$(command -v ipset)"
            fi
            ;;
        nft)
            _require_cmd nft
            NFT_BIN="$(command -v nft)"
            if [ "$IPSET_ENABLE" -eq 1 ]; then
                _log "IPSET_ENABLE ignored for nft backend."
            fi
            ;;
        pf)
            _require_cmd pfctl
            PFCTL_BIN="$(command -v pfctl)"
            if [ "$IPV6_ENABLE" -eq 0 ]; then
                _log "pf backend handles both IPv4/IPv6 tables. IPV6_ENABLE ignored."
            fi
            if [ "$RULE_POSITION" != "append" ]; then
                _log "RULE_POSITION ignored for pf backend."
            fi
            if [ "$IPSET_ENABLE" -eq 1 ]; then
                _log "IPSET_ENABLE ignored for pf backend."
            fi
            ;;
        *)
            _die "Unsupported FIREWALL_BACKEND: ${FIREWALL_BACKEND}"
            ;;
    esac

    mkdir -p "$TMP_DIR" "$STATE_DIR"

    local staged_list="${TMP_DIR}/blocked_ips.new"
    local active_list="$staged_list"

    _collect_feed_data "$staged_list"

    if [ ! -s "$staged_list" ]; then
        if [ -s "$CACHE_FILE" ]; then
            active_list="$CACHE_FILE"
            _log "No valid new feed data; using cached blocklist from ${CACHE_FILE}."
        else
            _die "No valid feed data and no cache available. Existing firewall rules left unchanged."
        fi
    else
        cp "$staged_list" "$CACHE_FILE"
        _log "Cached latest blocklist to ${CACHE_FILE}."
    fi

    case "$FIREWALL_BACKEND" in
        iptables) _apply_with_iptables "$active_list" ;;
        nft) _apply_with_nft "$active_list" ;;
        pf) _apply_with_pf "$active_list" ;;
    esac

    _log "Completed using backend: ${FIREWALL_BACKEND}."
}

if [[ "${BASH_SOURCE[0]}" = "$0" ]]; then
    main "$@"
fi
