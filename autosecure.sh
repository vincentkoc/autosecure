#!/usr/bin/env bash

set -euo pipefail

# Automatic pulling of spam lists to block IP's
# Copyright (C) 2013 David @cowgill
# Copyright (C) 2014 Vincent Koc @koconder
# Copyright (C) 2014 Volkan @volkan-k
# Copyright (C) 2016 Anasxrt @Anasxrt

# Runtime defaults
QUIET=0
DRY_RUN=0
DRY_RUN_OUTPUT=""
LOG_FILE="/var/log/autosecure.log"
TMP_DIR="/tmp/autosecure"
STATE_DIR="/var/lib/autosecure"
CACHE_FILE="${STATE_DIR}/blocked_ips.txt"
DOWNLOADER=""
AUTOSECURE_VERSION="${AUTOSECURE_VERSION:-dev}"

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

_print_banner() {
    cat <<'EOF'
 ▀▀█▄ ██ ██ ▀██▀▀ ▄███▄ ▄█▀▀▀ ▄█▀█▄ ▄████ ██ ██ ████▄ ▄█▀█▄
▄█▀██ ██ ██  ██   ██ ██ ▀███▄ ██▄█▀ ██    ██ ██ ██ ▀▀ ██▄█▀
▀█▄██ ▀██▀█  ██   ▀███▀ ▄▄▄█▀ ▀█▄▄▄ ▀████ ▀██▀█ ██    ▀█▄▄▄
EOF
}

_print_startup_header() {
    _print_banner
    printf '🔑 autosecure - made with love by Vincent Koc\n'
    printf '\n'
}

_print_help() {
    _print_startup_header
    cat <<'EOF'
Usage: autosecure.sh [options]

Options:
  -q              Quiet mode (cron-friendly).
  -n, --dry-run   Generate rules preview only; do not apply firewall changes.
  -o, --dry-run-output <file>
                  Write dry-run report to a specific file path.
  -h, --help      Show this help message and exit.
  -V, --version   Show version and exit.

Environment:
  AUTOSECURE_FIREWALL_BACKEND=auto|iptables|nft|pf
  AUTOSECURE_RULE_POSITION=append|top
  AUTOSECURE_XTABLES_WAIT=<seconds>
  AUTOSECURE_IPV6_ENABLE=0|1
  AUTOSECURE_IPSET_ENABLE=0|1
  AUTOSECURE_EXTRA_FEEDS=<url1,url2,...>
  AUTOSECURE_EGF=0|1
EOF
}

_print_version() {
    printf 'autosecure %s\n' "$AUTOSECURE_VERSION"
}

_log() {
    if [ "$QUIET" -eq 0 ]; then
        local msg
        msg="$(date "+%Y-%m-%d %H:%M:%S.%N"): $*"
        printf '%s\n' "$msg"
        ( printf '%s\n' "$msg" >> "$LOG_FILE" ) 2>/dev/null || true
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

_pfctl_exec() {
    local stderr_file="${TMP_DIR}/pfctl.stderr.$$.$RANDOM"

    if ! "$PFCTL_BIN" "$@" 2>"$stderr_file"; then
        cat "$stderr_file" >&2 || true
        rm -f "$stderr_file"
        return 1
    fi

    if [ -s "$stderr_file" ]; then
        awk '
            /Use of -f option, could result in flushing of rules/ { next }
            /present in the main ruleset added by the system at startup\./ { next }
            /See \/etc\/pf.conf for further details\./ { next }
            /pf already enabled/ { next }
            /^$/ { next }
            { print }
        ' "$stderr_file" >&2
    fi

    rm -f "$stderr_file"
}

_parse_dshield_file() {
    local file="$1"
    awk '/^[0-9]/ { print $1 "/" $3 }' "$file" | sort -u
}

_parse_static_blocklist_file() {
    local file="$1"
    awk '
        /^(;|#|$)/ { next }
        {
            ip = $1
            sub(/\r$/, "", ip)
            if (length(ip) > 64) next
            print ip
        }
    ' "$file" | sort -u
}

_parse_alienvault_file() {
    local file="$1"
    awk -F'#' '/^[0-9]/ { gsub(/[[:space:]]+/, "", $1); print $1 }' "$file" | sort -u
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

_pf_is_enabled() {
    "$PFCTL_BIN" -s info 2>/dev/null | awk -F': ' '/^Status:/ { print $2 }' | grep -qi '^enabled$'
}

_count_nonempty_lines() {
    local file="$1"
    awk 'NF { c++ } END { print c + 0 }' "$file"
}

_feed_log_label() {
    local url="$1"
    local label="${url#http://}"
    label="${label#https://}"
    label="${label#www.}"
    printf '%s\n' "$label"
}

_count_family_entries() {
    local family="$1"
    local list_file="$2"
    local count=0
    local ip=""
    while IFS= read -r ip; do
        [ -n "$ip" ] || continue
        if _ip_matches_family "$family" "$ip"; then
            count=$((count + 1))
        fi
    done < "$list_file"
    printf '%s\n' "$count"
}

_render_iptables_dry_run() {
    local list_file="$1"
    local out_file="$2"
    local ip=""
    local family=""
    local fwbin=""

    {
        echo "[iptables] chain preparation"
        echo "${IPTABLES_BIN} -w ${XTABLES_WAIT} -N ${CHAIN} || ${IPTABLES_BIN} -w ${XTABLES_WAIT} -F ${CHAIN}"
        echo "${IPTABLES_BIN} -w ${XTABLES_WAIT} -N ${CHAINACT} || ${IPTABLES_BIN} -w ${XTABLES_WAIT} -F ${CHAINACT}"
        if [ "$RULE_POSITION" = "top" ]; then
            echo "${IPTABLES_BIN} -w ${XTABLES_WAIT} -I INPUT -j ${CHAIN}"
            echo "${IPTABLES_BIN} -w ${XTABLES_WAIT} -I FORWARD -j ${CHAIN}"
            if [ "$EGF" -ne 0 ]; then
                echo "${IPTABLES_BIN} -w ${XTABLES_WAIT} -I OUTPUT -j ${CHAIN}"
            fi
        else
            echo "${IPTABLES_BIN} -w ${XTABLES_WAIT} -A INPUT -j ${CHAIN}"
            echo "${IPTABLES_BIN} -w ${XTABLES_WAIT} -A FORWARD -j ${CHAIN}"
            if [ "$EGF" -ne 0 ]; then
                echo "${IPTABLES_BIN} -w ${XTABLES_WAIT} -A OUTPUT -j ${CHAIN}"
            fi
        fi
        echo "${IPTABLES_BIN} -w ${XTABLES_WAIT} -A ${CHAINACT} -j LOG --log-prefix \"[AUTOSECURE BLOCK] \" -m limit --limit 3/min --limit-burst 10"
        echo "${IPTABLES_BIN} -w ${XTABLES_WAIT} -A ${CHAINACT} -j DROP"
    } >> "$out_file"

    for family in v4 v6; do
        if [ "$family" = "v6" ] && [ "$IPV6_ENABLE" -ne 1 ]; then
            continue
        fi
        if [ "$family" = "v4" ]; then
            fwbin="$IPTABLES_BIN"
        else
            fwbin="$IP6TABLES_BIN"
        fi

        if [ "$IPSET_ENABLE" -eq 1 ]; then
            {
                echo
                echo "[iptables/${family}] ipset mode"
                if [ "$family" = "v4" ]; then
                    echo "${IPSET_BIN} create ${IPSET_V4_NAME} hash:net family inet -exist"
                    echo "${IPSET_BIN} flush ${IPSET_V4_NAME}"
                    echo "${fwbin} -w ${XTABLES_WAIT} -A ${CHAIN} -m set --match-set ${IPSET_V4_NAME} src -j ${CHAINACT}"
                    if [ "$EGF" -ne 0 ]; then
                        echo "${fwbin} -w ${XTABLES_WAIT} -A ${CHAIN} -m set --match-set ${IPSET_V4_NAME} dst -j ${CHAINACT}"
                    fi
                else
                    echo "${IPSET_BIN} create ${IPSET_V6_NAME} hash:net family inet6 -exist"
                    echo "${IPSET_BIN} flush ${IPSET_V6_NAME}"
                    echo "${fwbin} -w ${XTABLES_WAIT} -A ${CHAIN} -m set --match-set ${IPSET_V6_NAME} src -j ${CHAINACT}"
                    if [ "$EGF" -ne 0 ]; then
                        echo "${fwbin} -w ${XTABLES_WAIT} -A ${CHAIN} -m set --match-set ${IPSET_V6_NAME} dst -j ${CHAINACT}"
                    fi
                fi
            } >> "$out_file"

            while IFS= read -r ip; do
                [ -n "$ip" ] || continue
                if ! _ip_matches_family "$family" "$ip"; then
                    continue
                fi
                if [ "$family" = "v4" ]; then
                    echo "${IPSET_BIN} add ${IPSET_V4_NAME} ${ip} -exist" >> "$out_file"
                else
                    echo "${IPSET_BIN} add ${IPSET_V6_NAME} ${ip} -exist" >> "$out_file"
                fi
            done < "$list_file"
        else
            {
                echo
                echo "[iptables/${family}] direct rules"
            } >> "$out_file"

            while IFS= read -r ip; do
                [ -n "$ip" ] || continue
                if ! _ip_matches_family "$family" "$ip"; then
                    continue
                fi
                echo "${fwbin} -w ${XTABLES_WAIT} -A ${CHAIN} -s ${ip} -j ${CHAINACT}" >> "$out_file"
                if [ "$EGF" -ne 0 ]; then
                    echo "${fwbin} -w ${XTABLES_WAIT} -A ${CHAIN} -d ${ip} -j ${CHAINACT}" >> "$out_file"
                fi
            done < "$list_file"
        fi
    done
}

_render_nft_dry_run() {
    local list_file="$1"
    local out_file="$2"
    local ip=""
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

    {
        echo "[nft] ruleset preview"
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
        echo
        echo "would run: ${NFT_BIN} -f <rules-file>"
    } >> "$out_file"
}

_render_pf_dry_run() {
    local list_file="$1"
    local out_file="$2"

    {
        echo "[pf] anchor preview"
        echo "anchor: ${PF_ANCHOR}"
        echo "anchor file: ${PF_ANCHOR_FILE}"
        echo
        echo "anchor content:"
        echo "table <autosecure_bad_hosts> persist"
        echo "block in quick from <autosecure_bad_hosts> to any"
        if [ "$EGF" -ne 0 ]; then
            echo "block out quick from any to <autosecure_bad_hosts>"
        fi
        echo
        echo "would run: ${PFCTL_BIN} -a ${PF_ANCHOR} -f ${PF_ANCHOR_FILE}"
        echo "would run: ${PFCTL_BIN} -a ${PF_ANCHOR} -t autosecure_bad_hosts -T replace -f <list-file>"
        echo "would run: ${PFCTL_BIN} -e"
        echo
        echo "block entries:"
        cat "$list_file"
    } >> "$out_file"
}

_write_dry_run_report() {
    local list_file="$1"
    local report_file="${DRY_RUN_OUTPUT}"
    local ts=""
    local total_count=0
    local v4_count=0
    local v6_count=0

    if [ -z "$report_file" ]; then
        ts="$(date "+%Y%m%d-%H%M%S")"
        report_file="${TMP_DIR}/autosecure-dryrun-${ts}.txt"
    fi

    total_count="$(awk 'NF{c++} END {print c+0}' "$list_file")"
    v4_count="$(_count_family_entries v4 "$list_file")"
    v6_count="$(_count_family_entries v6 "$list_file")"

    {
        echo "AUTOSECURE DRY RUN"
        echo "generated_at: $(date "+%Y-%m-%d %H:%M:%S")"
        echo "backend: ${FIREWALL_BACKEND}"
        echo "entries_total: ${total_count}"
        echo "entries_v4: ${v4_count}"
        echo "entries_v6: ${v6_count}"
        echo "rule_position: ${RULE_POSITION}"
        echo "ipv6_enable: ${IPV6_ENABLE}"
        echo "ipset_enable: ${IPSET_ENABLE}"
        echo "egf: ${EGF}"
        echo
    } > "$report_file"

    case "$FIREWALL_BACKEND" in
        iptables) _render_iptables_dry_run "$list_file" "$report_file" ;;
        nft) _render_nft_dry_run "$list_file" "$report_file" ;;
        pf) _render_pf_dry_run "$list_file" "$report_file" ;;
    esac

    printf '%s\n' "$report_file"
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

_ensure_tmp_dir() {
    if [ ! -d "$TMP_DIR" ]; then
        mkdir -p "$TMP_DIR"
    fi

    if [ ! -w "$TMP_DIR" ]; then
        TMP_DIR="$(mktemp -d /tmp/autosecure.XXXXXX)"
    fi
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
        "https://feeds.dshield.org/block.txt"
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
        "https://reputation.alienvault.com/reputation.data"
    )

    local files=(
        "${TMP_DIR}/spamhaus_drop.txt"
        "${TMP_DIR}/spamhaus_edrop.txt"
        "${TMP_DIR}/dshield_drop.txt"
        "${TMP_DIR}/feodo_ipblocklist.txt"
        "${TMP_DIR}/alienvault_reputation.txt"
    )

    local parsers=(
        "static"
        "static"
        "dshield"
        "static"
        "alienvault"
    )

    while IFS= read -r extra; do
        urls+=("$extra")
        files+=("${TMP_DIR}/extra_$(printf '%03d' "${#files[@]}").txt")
        parsers+=("static")
    done < <(_parse_extra_feeds)

    : > "$output_file"

    for idx in "${!urls[@]}"; do
        local url="${urls[$idx]}"
        local file="${files[$idx]}"
        local parsed_file=""
        local feed_num=$((idx + 1))
        local log_label
        log_label="$(_feed_log_label "$url")"

        _log "[${feed_num}] Downloading ${log_label} to ${TMP_DIR}/"
        if ! _download_file "$url" "$file"; then
            _log "[${feed_num}] Failed to download ${log_label}. Skipping this source."
            continue
        fi

        if [ ! -s "$file" ]; then
            _log "[${feed_num}] Downloaded file is empty: ${file}. Skipping."
            rm -f "$file"
            continue
        fi

        _log "[${feed_num}] Parsing hosts in ${file}..."
        local parser="${parsers[$idx]}"
        parsed_file="${TMP_DIR}/parsed_${feed_num}.txt"
        : > "$parsed_file"
        case "$parser" in
            dshield)
                _parse_dshield_file "$file" > "$parsed_file"
                ;;
            alienvault)
                _parse_alienvault_file "$file" > "$parsed_file"
                ;;
            *)
                _parse_static_blocklist_file "$file" > "$parsed_file"
                ;;
        esac

        local parsed_count=0
        local valid_count=0
        local invalid_count=0
        parsed_count="$(_count_nonempty_lines "$parsed_file")"

        while IFS= read -r ip; do
            [ -n "$ip" ] || continue
            if _is_valid_ip_or_cidr "$ip"; then
                printf '%s\n' "$ip" >> "$output_file"
                valid_count=$((valid_count + 1))
            else
                invalid_count=$((invalid_count + 1))
            fi
        done < "$parsed_file"

        _log "[${feed_num}] Stats: parsed=${parsed_count}, valid=${valid_count}, invalid=${invalid_count}"
        rm -f "$parsed_file"

        _log "[${feed_num}] Done parsing ${file}. Removing..."
        rm -f "$file"
    done

    local pre_dedupe_count=0
    local final_count=0
    pre_dedupe_count="$(_count_nonempty_lines "$output_file")"
    sort -u -o "$output_file" "$output_file"
    final_count="$(_count_nonempty_lines "$output_file")"
    _log "Feed summary: collected=${pre_dedupe_count}, unique=${final_count}, deduped=$((pre_dedupe_count - final_count))"
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

    local v4_count=0
    local v6_count=0
    if [ "$first_v4" -eq 0 ]; then
        v4_count="$(_count_family_entries v4 "$list_file")"
    fi
    if [ "$first_v6" -eq 0 ]; then
        v6_count="$(_count_family_entries v6 "$list_file")"
    fi

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
    _log "[nft] Applied nftables table '${NFT_TABLE}' (entries: v4=${v4_count}, v6=${v6_count})."
}

_pf_bootstrap_anchor() {
    local anchor_line="anchor \"${PF_ANCHOR}\""
    local load_line="load anchor \"${PF_ANCHOR}\" from \"${PF_ANCHOR_FILE}\""
    local changed=0

    touch "$PF_ANCHOR_FILE"

    if ! grep -qF "$anchor_line" /etc/pf.conf; then
        printf '%s\n' "$anchor_line" >> /etc/pf.conf
        _log "[pf] Added anchor line to /etc/pf.conf."
        changed=1
    fi

    if ! grep -qF "$load_line" /etc/pf.conf; then
        printf '%s\n' "$load_line" >> /etc/pf.conf
        _log "[pf] Added load anchor line to /etc/pf.conf."
        changed=1
    fi

    if [ "$changed" -eq 1 ]; then
        if ! "$PFCTL_BIN" -nf /etc/pf.conf >/dev/null 2>&1; then
            _die "Failed to validate /etc/pf.conf after pf bootstrap."
        fi

        _pfctl_exec -q -f /etc/pf.conf >/dev/null
    fi
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

    _pfctl_exec -q -a "$PF_ANCHOR" -f "$PF_ANCHOR_FILE" >/dev/null
    _pfctl_exec -q -a "$PF_ANCHOR" -t autosecure_bad_hosts -T replace -f "$list_file" >/dev/null
    if ! _pf_is_enabled; then
        _pfctl_exec -q -e >/dev/null || true
    fi

    local total_count=0
    local v4_count=0
    local v6_count=0
    total_count="$(_count_nonempty_lines "$list_file")"
    v4_count="$(_count_family_entries v4 "$list_file")"
    v6_count="$(_count_family_entries v6 "$list_file")"
    _log "[pf] Applied anchor '${PF_ANCHOR}' (entries: total=${total_count}, v4=${v4_count}, v6=${v6_count})."
}

main() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -q)
                QUIET=1
                shift
                ;;
            -n|--dry-run)
                DRY_RUN=1
                shift
                ;;
            -o|--dry-run-output)
                if [ "$#" -lt 2 ]; then
                    _die "--dry-run-output requires a file path"
                fi
                DRY_RUN_OUTPUT="$2"
                shift 2
                ;;
            -h|--help)
                _print_help
                exit 0
                ;;
            -V|--version)
                _print_version
                exit 0
                ;;
            *)
                _die "Unknown option: $1 (use --help)"
                ;;
        esac
    done

    if [ "${EUID:-$(id -u)}" -ne 0 ] && [ "$DRY_RUN" -ne 1 ]; then
        _die "This script must run as root."
    fi

    if [ "$QUIET" -eq 0 ] && [ -t 1 ]; then
        _print_startup_header
    fi

    _validate_settings
    _select_downloader
    _require_cmd awk
    _require_cmd grep
    _require_cmd sort
    _require_cmd mkdir
    _require_cmd date

    _detect_firewall_backend

    case "$FIREWALL_BACKEND" in
        iptables)
            if command -v iptables >/dev/null 2>&1; then
                IPTABLES_BIN="$(command -v iptables)"
            elif [ "$DRY_RUN" -eq 1 ]; then
                IPTABLES_BIN="iptables"
            else
                _die "Required command not found: iptables"
            fi
            if [ "$IPV6_ENABLE" -eq 1 ]; then
                if command -v ip6tables >/dev/null 2>&1; then
                    IP6TABLES_BIN="$(command -v ip6tables)"
                elif [ "$DRY_RUN" -eq 1 ]; then
                    IP6TABLES_BIN="ip6tables"
                else
                    _die "Required command not found: ip6tables"
                fi
            fi
            if [ "$IPSET_ENABLE" -eq 1 ]; then
                if command -v ipset >/dev/null 2>&1; then
                    IPSET_BIN="$(command -v ipset)"
                elif [ "$DRY_RUN" -eq 1 ]; then
                    IPSET_BIN="ipset"
                else
                    _die "Required command not found: ipset"
                fi
            fi
            ;;
        nft)
            if command -v nft >/dev/null 2>&1; then
                NFT_BIN="$(command -v nft)"
            elif [ "$DRY_RUN" -eq 1 ]; then
                NFT_BIN="nft"
            else
                _die "Required command not found: nft"
            fi
            if [ "$IPSET_ENABLE" -eq 1 ]; then
                _log "IPSET_ENABLE ignored for nft backend."
            fi
            ;;
        pf)
            if command -v pfctl >/dev/null 2>&1; then
                PFCTL_BIN="$(command -v pfctl)"
            elif [ "$DRY_RUN" -eq 1 ]; then
                PFCTL_BIN="pfctl"
            else
                _die "Required command not found: pfctl"
            fi
            if [ "$IPV6_ENABLE" -eq 0 ]; then
                _log "pf backend handles both IPv4/IPv6 tables. 'IPV6_ENABLE' ignored."
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

    _ensure_tmp_dir
    if [ "$DRY_RUN" -ne 1 ]; then
        mkdir -p "$STATE_DIR"
    fi

    local staged_list="${TMP_DIR}/blocked_ips.new"
    local active_list="$staged_list"
    local dry_run_report=""

    _collect_feed_data "$staged_list"

    if [ ! -s "$staged_list" ]; then
        if [ -s "$CACHE_FILE" ]; then
            active_list="$CACHE_FILE"
            local cache_count=0
            cache_count="$(_count_nonempty_lines "$CACHE_FILE")"
            _log "No valid new feed data; using cached blocklist from ${CACHE_FILE} (${cache_count} entries)."
        else
            _die "No valid feed data and no cache available. Existing firewall rules left unchanged."
        fi
    else
        if [ "$DRY_RUN" -ne 1 ]; then
            cp "$staged_list" "$CACHE_FILE"
            _log "Cached latest blocklist to ${CACHE_FILE}."
        else
            _log "Dry-run mode enabled; cache update skipped."
        fi
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        dry_run_report="$(_write_dry_run_report "$active_list")"
        _log "Dry-run report written to ${dry_run_report}"
        _log "No firewall changes were applied."
        _log "Completed using backend: ${FIREWALL_BACKEND} (dry-run)."
        exit 0
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
