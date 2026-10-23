#!/usr/bin/env bash
# =============================================================================
# ddos.sh — Adaptive connection-count based IP blocker
#
#   DEFENSIVE TOOLING ONLY. Reads the local kernel's connection table and
#   modifies the host's own firewall. Never sends traffic to any remote host.
#
#   Successor to DDOS-Deflate 0.6 (Zaf, inetbase.com, ~2012). The original
#   installer downloaded files over plaintext HTTP from a domain that no
#   longer exists; this rewrite ships everything in the script itself.
#
#   Version: 2.0.0
#   Author:  SL_CE"I_"
#
#   Sections:
#     §1  Constants
#     §2  Logging + JSON events
#     §3  Config loader + validator
#     §4  Locking
#     §5  IP / CIDR helpers
#     §6  Firewall backend (ipset + iptables)
#     §7  List loaders
#     §8  Connection sampler (ss | netstat)
#     §9  Persistence tracker
#     §10 Ban manager (TTL, recidivism)
#     §11 Notifier
#     §12 Signal traps
#     §13 Subcommands
#     §14 Main loop
# =============================================================================

set -euo pipefail
umask 022

# =============================================================================
# §1  Constants
# =============================================================================
readonly SCRIPT_NAME="ddos"
readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_AUTHOR='SL_CE"I_"'
readonly DEFAULT_CONF="/etc/ddos/ddos.conf"
readonly DEFAULT_STATE="/var/lib/ddos"
readonly DEFAULT_LOG="/var/log/ddos"
readonly DEFAULT_INSTALL_DIR="/usr/local/ddos"
readonly DEFAULT_BIN_SYMLINK="/usr/local/sbin/ddos"
readonly DEFAULT_NEVER_BAN="/etc/ddos/ignore.ip.list"
readonly DEFAULT_MANUAL_BAN="/etc/ddos/block.ip.list"

readonly VALID_CONFIG_KEYS="SAMPLE_INTERVAL CONN_THRESHOLD PERSIST_CYCLES \
MIN_CONNECTIONS SOCKET_STATES SCAN_THRESHOLD DISTINCT_PORTS_THRESHOLD \
DEFAULT_TTL TTL_STEP MAX_TTL NEVER_BAN MANUAL_BAN PROTECTED_RANGES \
IPSET_NAME IPSET_NAME6 NOTIFY DIGEST_MINUTES MAIL_TO WEBHOOK_URL \
STATE_DIR LOGS_DIR"

CONFIG_FILE="$DEFAULT_CONF"
ACTION="run"
ARG1=""
DRY_RUN="no"
VERBOSE="no"
CURRENT_TIME=0

# =============================================================================
# §2  Logging + JSON events
# =============================================================================
EVENTS_LOG=""

log() {
    printf '%s ddos[%d] %s\n' "$(date -u +%FT%TZ)" "$$" "$*" >&2
}

verbose() {
    [[ "$VERBOSE" == "yes" ]] && log "$@"
    return 0
}

die() {
    log "FATAL: $*"
    exit 1
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

json_escape() {
    local s=$1
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

log_json() {
    local event=$1; shift
    [[ -n "$EVENTS_LOG" ]] || return 0
    local line
    line=$(printf '{"ts":"%s","pid":%d,"event":"%s"' \
        "$(date -u +%FT%TZ)" "$$" "$(json_escape "$event")")
    local kv k v
    for kv in "$@"; do
        k="${kv%%=*}"
        v="${kv#*=}"
        line+=$(printf ',"%s":"%s"' "$(json_escape "$k")" "$(json_escape "$v")")
    done
    line+='}'
    printf '%s\n' "$line" >> "$EVENTS_LOG"
}

# =============================================================================
# §3  Config loader + validator
# =============================================================================
: "${SAMPLE_INTERVAL:=60}"
: "${CONN_THRESHOLD:=100}"
: "${PERSIST_CYCLES:=3}"
: "${MIN_CONNECTIONS:=10}"
: "${SOCKET_STATES:=ESTAB,SYN_RECV}"
: "${SCAN_THRESHOLD:=0}"
: "${DISTINCT_PORTS_THRESHOLD:=20}"
: "${DEFAULT_TTL:=3600}"
: "${TTL_STEP:=2}"
: "${MAX_TTL:=604800}"
: "${NEVER_BAN:=$DEFAULT_NEVER_BAN}"
: "${MANUAL_BAN:=$DEFAULT_MANUAL_BAN}"
: "${PROTECTED_RANGES:=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,169.254.0.0/16,::1/128,fe80::/10}"
: "${IPSET_NAME:=ddos4}"
: "${IPSET_NAME6:=ddos6}"
: "${NOTIFY:=digest}"
: "${DIGEST_MINUTES:=15}"
: "${MAIL_TO:=admin@localhost}"
: "${WEBHOOK_URL:=}"
: "${STATE_DIR:=$DEFAULT_STATE}"
: "${LOGS_DIR:=$DEFAULT_LOG}"

is_valid_config_key() {
    [[ " ${VALID_CONFIG_KEYS} " == *" $1 "* ]]
}

load_config() {
    local file=$1 line key val
    [[ -f "$file" ]] || return 0   # config optional; defaults apply
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$line" || "$line" == \#* ]] && continue
        [[ "$line" =~ ^([A-Z][A-Z0-9_]*)=(.*)$ ]] || continue
        key="${BASH_REMATCH[1]}"
        val="${BASH_REMATCH[2]}"
        [[ "$val" =~ ^\"(.*)\"$ ]] && val="${BASH_REMATCH[1]}"
        [[ "$val" =~ ^\'(.*)\'$ ]] && val="${BASH_REMATCH[1]}"
        if is_valid_config_key "$key"; then
            printf -v "$key" '%s' "$val"
        else
            log "warning: unknown config key ignored: $key"
        fi
    done < "$file"
}

validate_config() {
    [[ "$SAMPLE_INTERVAL" =~ ^[0-9]+$ ]] && (( SAMPLE_INTERVAL >= 5 )) \
        || die "SAMPLE_INTERVAL must be integer >= 5 seconds"
    [[ "$CONN_THRESHOLD" =~ ^[0-9]+$ ]] && (( CONN_THRESHOLD >= 2 )) \
        || die "CONN_THRESHOLD must be integer >= 2"
    [[ "$PERSIST_CYCLES" =~ ^[0-9]+$ ]] && (( PERSIST_CYCLES >= 1 )) \
        || die "PERSIST_CYCLES must be integer >= 1"
    [[ "$MIN_CONNECTIONS" =~ ^[0-9]+$ ]] && (( MIN_CONNECTIONS >= 1 )) \
        || die "MIN_CONNECTIONS must be integer >= 1"
    (( MIN_CONNECTIONS <= CONN_THRESHOLD )) \
        || die "MIN_CONNECTIONS must be <= CONN_THRESHOLD"
    [[ "$NOTIFY" =~ ^(none|digest|per-ip)$ ]] \
        || die "NOTIFY must be none|digest|per-ip"
    [[ "$DEFAULT_TTL" =~ ^[0-9]+$ ]] || die "DEFAULT_TTL must be integer"
    [[ "$MAX_TTL" =~ ^[0-9]+$ ]]     || die "MAX_TTL must be integer"
}

# =============================================================================
# §4  Locking
# =============================================================================
acquire_lock() {
    mkdir -p "$STATE_DIR"
    local lock="$STATE_DIR/ddos.lock" pidfile="$STATE_DIR/ddos.pid"
    exec 9>"$lock"
    if ! flock -n 9; then
        local pid=""
        [[ -f "$pidfile" ]] && pid=$(cat "$pidfile" 2>/dev/null || true)
        die "another instance is running${pid:+ (pid $pid)}"
    fi
    printf '%s\n' "$$" > "$pidfile"
}

release_lock() {
    rm -f "$STATE_DIR/ddos.pid"
}

# =============================================================================
# §5  IP / CIDR helpers
# =============================================================================
is_ipv4() {
    local ip=$1 octet
    [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] \
        || return 1
    for octet in "${BASH_REMATCH[@]:1:4}"; do
        (( octet <= 255 )) || return 1
    done
    return 0
}

is_ipv6() {
    [[ "$1" == *:* ]] || return 1
    [[ "$1" =~ ^[0-9a-fA-F:]+$ ]] || return 1
    [[ "$1" == *":::"* ]] && return 1
    [[ "$1" =~ [0-9a-fA-F] ]] || return 1
    return 0
}

is_ip() { is_ipv4 "$1" || is_ipv6 "$1"; }

is_never_ban() {
    if is_ipv4 "$1"; then
        ipset test "${IPSET_NAME}_never4" "$1" 2>/dev/null
    else
        ipset test "${IPSET_NAME6}_never6" "$1" 2>/dev/null
    fi
}

is_manual_ban() {
    if is_ipv4 "$1"; then
        ipset test "${IPSET_NAME}_manual4" "$1" 2>/dev/null
    else
        ipset test "${IPSET_NAME6}_manual6" "$1" 2>/dev/null
    fi
}

# =============================================================================
# §6  Firewall backend
# =============================================================================
fw_init() {
    need_cmd ipset
    need_cmd iptables

    ipset create "${IPSET_NAME}"      hash:ip  family inet  timeout "$DEFAULT_TTL" maxelem 262144 -exist
    ipset create "${IPSET_NAME6}"     hash:ip  family inet6 timeout "$DEFAULT_TTL" maxelem 262144 -exist
    ipset create "${IPSET_NAME}_never4"   hash:net family inet  -exist
    ipset create "${IPSET_NAME6}_never6"  hash:net family inet6 -exist
    ipset create "${IPSET_NAME}_manual4"  hash:net family inet  -exist
    ipset create "${IPSET_NAME6}_manual6" hash:net family inet6 -exist

    iptables -nL DDOS_DEFLATE >/dev/null 2>&1 || iptables -N DDOS_DEFLATE
    iptables -C INPUT -j DDOS_DEFLATE 2>/dev/null || iptables -I INPUT 1 -j DDOS_DEFLATE
    iptables -C DDOS_DEFLATE -m set --match-set "${IPSET_NAME}" src \
        -m comment --comment "ddos-deflate" -j DROP 2>/dev/null \
        || iptables -A DDOS_DEFLATE -m set --match-set "${IPSET_NAME}" src \
            -m comment --comment "ddos-deflate" -j DROP

    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -nL DDOS_DEFLATE >/dev/null 2>&1 || ip6tables -N DDOS_DEFLATE
        ip6tables -C INPUT -j DDOS_DEFLATE 2>/dev/null || ip6tables -I INPUT 1 -j DDOS_DEFLATE
        ip6tables -C DDOS_DEFLATE -m set --match-set "${IPSET_NAME6}" src \
            -m comment --comment "ddos-deflate" -j DROP 2>/dev/null \
            || ip6tables -A DDOS_DEFLATE -m set --match-set "${IPSET_NAME6}" src \
                -m comment --comment "ddos-deflate" -j DROP
    fi
}

fw_ban() {
    local ip=$1 ttl=$2
    if is_ipv4 "$ip"; then
        ipset add "${IPSET_NAME}" "$ip" timeout "$ttl" -exist
    elif is_ipv6 "$ip"; then
        ipset add "${IPSET_NAME6}" "$ip" timeout "$ttl" -exist
    else
        return 1
    fi
}

fw_unban() {
    if is_ipv4 "$1"; then
        ipset del "${IPSET_NAME}" "$1" 2>/dev/null
    elif is_ipv6 "$1"; then
        ipset del "${IPSET_NAME6}" "$1" 2>/dev/null
    else
        return 1
    fi
}

fw_member() {
    if is_ipv4 "$1"; then
        ipset test "${IPSET_NAME}" "$1" 2>/dev/null
    else
        ipset test "${IPSET_NAME6}" "$1" 2>/dev/null
    fi
}

fw_teardown() {
    command -v iptables >/dev/null 2>&1 && {
        iptables -D INPUT -j DDOS_DEFLATE 2>/dev/null || true
        iptables -F DDOS_DEFLATE 2>/dev/null || true
        iptables -X DDOS_DEFLATE 2>/dev/null || true
    }
    command -v ip6tables >/dev/null 2>&1 && {
        ip6tables -D INPUT -j DDOS_DEFLATE 2>/dev/null || true
        ip6tables -F DDOS_DEFLATE 2>/dev/null || true
        ip6tables -X DDOS_DEFLATE 2>/dev/null || true
    }
    command -v ipset >/dev/null 2>&1 && {
        local s
        for s in "${IPSET_NAME}" "${IPSET_NAME6}" \
                 "${IPSET_NAME}_never4"   "${IPSET_NAME6}_never6" \
                 "${IPSET_NAME}_manual4"  "${IPSET_NAME6}_manual6"; do
            ipset destroy "$s" 2>/dev/null || true
        done
    }
}

# =============================================================================
# §7  List loaders
# =============================================================================
_load_list_into_set() {
    local file=$1 set4=$2 set6=$3 label=$4
    local line entry n=0 skip=0
    [[ -f "$file" ]] || { verbose "list not found: $file"; return 0; }
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" ]] && continue
        entry="$line"
        if [[ "$entry" =~ /([0-9]+)$ ]]; then
            local pfx="${BASH_REMATCH[1]}"
            if (( pfx == 0 )) || { (( pfx < 8 )) && [[ "${FORCE_BROAD:-no}" != "yes" ]]; }; then
                log "refusing overly broad entry in $label: $entry"
                skip=$((skip+1)); continue
            fi
        fi
        if [[ "$entry" == *:* ]]; then
            ipset add "$set6" "$entry" -exist 2>/dev/null \
                || { log "invalid v6 in $label: $entry"; skip=$((skip+1)); continue; }
        else
            ipset add "$set4" "$entry" -exist 2>/dev/null \
                || { log "invalid v4 in $label: $entry"; skip=$((skip+1)); continue; }
        fi
        n=$((n+1))
    done < "$file"
    log "loaded $label from $file ($n entries, $skip skipped)"
}

_load_csv_ranges() {
    local csv=$1 set4=$2 set6=$3 label=$4 entry n=0 skip=0
    for entry in ${csv//,/ }; do
        [[ -z "$entry" ]] && continue
        if [[ "$entry" == *:* ]]; then
            ipset add "$set6" "$entry" -exist 2>/dev/null || { skip=$((skip+1)); continue; }
        else
            ipset add "$set4" "$entry" -exist 2>/dev/null || { skip=$((skip+1)); continue; }
        fi
        n=$((n+1))
    done
    log "loaded $label ($n entries, $skip skipped)"
}

load_lists() {
    _load_csv_ranges "$PROTECTED_RANGES" \
        "${IPSET_NAME}_never4"   "${IPSET_NAME6}_never6"   "protected-ranges"
    _load_list_into_set "$NEVER_BAN" \
        "${IPSET_NAME}_never4"   "${IPSET_NAME6}_never6"   "whitelist"
    _load_list_into_set "$MANUAL_BAN" \
        "${IPSET_NAME}_manual4"  "${IPSET_NAME6}_manual6"  "blacklist"
}

# =============================================================================
# §8  Connection sampler
# =============================================================================
detect_sampler() {
    if command -v ss >/dev/null 2>&1; then
        echo "ss"
    elif command -v netstat >/dev/null 2>&1; then
        echo "netstat"
    else
        echo ""
    fi
}

sample_connections_raw() {
    local tool
    tool=$(detect_sampler)
    case "$tool" in
        ss)      ss -H -ntu 2>/dev/null || true ;;
        netstat) netstat -ntu 2>/dev/null | tail -n +3 || true ;;
        *)       return 1 ;;
    esac
}

# Emits "count ip" lines for each peer IP with count >= MIN_CONNECTIONS.
count_by_peer() {
    local tool
    tool=$(detect_sampler)
    [[ -z "$tool" ]] && return 1

    local states_csv="${SOCKET_STATES:-ESTAB,SYN_RECV}"
    sample_connections_raw | awk -v tool="$tool" -v states="$states_csv" -v minc="$MIN_CONNECTIONS" '
    BEGIN {
        n = split(states, arr, ",")
        for (i = 1; i <= n; i++) want[arr[i]] = 1
    }
    {
        if (tool == "ss") {
            state = $2
            peer_field = $6
        } else {
            state = $6
            peer_field = $5
        }

        if (!(state in want)) next
        if (peer_field == "" || peer_field ~ /\*$/) next

        peer = peer_field
        sub(/:[0-9]+$/, "", peer)
        gsub(/[\[\]]/, "", peer)
        if (peer == "0.0.0.0" || peer == "::" || peer == "") next

        count[peer]++
    }
    END {
        for (ip in count)
            if (count[ip] >= minc) printf "%d %s\n", count[ip], ip
    }'
}

# Emits "distinct_port_count ip" lines for optional port-scan detection.
count_distinct_ports_by_peer() {
    local tool
    tool=$(detect_sampler)
    [[ -z "$tool" ]] && return 1

    local states_csv="${SOCKET_STATES:-ESTAB,SYN_RECV}"
    sample_connections_raw | awk -v tool="$tool" -v states="$states_csv" '
    BEGIN {
        n = split(states, arr, ",")
        for (i = 1; i <= n; i++) want[arr[i]] = 1
    }
    {
        if (tool == "ss") {
            state = $2
            local_field = $5
            peer_field = $6
        } else {
            state = $6
            local_field = $4
            peer_field = $5
        }

        if (!(state in want)) next
        if (peer_field == "" || peer_field ~ /\*$/) next

        peer = peer_field
        sub(/:[0-9]+$/, "", peer)
        gsub(/[\[\]]/, "", peer)
        if (peer == "0.0.0.0" || peer == "::" || peer == "") next

        port = local_field
        sub(/^.*:/, "", port)
        gsub(/[^0-9]/, "", port)
        if (port == "" || port == 0) next

        key = peer SUBSEP port
        if (key in seen) next
        seen[key] = 1
        ports[peer]++
    }
    END {
        for (ip in ports) printf "%d %s\n", ports[ip], ip
    }'
}

# =============================================================================
# §9  Persistence tracker
# =============================================================================
declare -A STREAK=()
declare -A STREAK_TS=()
declare -A LAST_COUNT=()
declare -A CYCLE_COUNT=()

track_cycle() {
    local counts=$1
    CYCLE_COUNT=()

    local count ip
    while read -r count ip; do
        [[ -z "$ip" ]] && continue
        is_ip "$ip" || continue
        is_never_ban "$ip" && continue
        is_manual_ban "$ip" && continue

        CYCLE_COUNT[$ip]=$count
        LAST_COUNT[$ip]=$count

        if (( count >= CONN_THRESHOLD )); then
            STREAK[$ip]=$(( ${STREAK[$ip]:-0} + 1 ))
            STREAK_TS[$ip]=$CURRENT_TIME
            verbose "tracking $ip: count=$count streak=${STREAK[$ip]}/${PERSIST_CYCLES}"
        else
            if [[ -n "${STREAK[$ip]:-}" ]]; then
                verbose "reset $ip: count=$count below threshold"
                unset "STREAK[$ip]" "STREAK_TS[$ip]"
            fi
        fi
    done <<< "$counts"

    local cutoff=$(( CURRENT_TIME - SAMPLE_INTERVAL * (PERSIST_CYCLES + 2) * 2 ))
    for ip in "${!STREAK_TS[@]}"; do
        if (( ${STREAK_TS[$ip]:-0} < cutoff )); then
            unset "STREAK[$ip]" "STREAK_TS[$ip]" "LAST_COUNT[$ip]"
        fi
    done
}

apply_bans_from_streaks() {
    local ip
    for ip in "${!STREAK[@]}"; do
        if (( STREAK[$ip] >= PERSIST_CYCLES )) && ! fw_member "$ip"; then
            ban_ip "$ip" "count=${LAST_COUNT[$ip]},cycles=${STREAK[$ip]}"
            unset "STREAK[$ip]" "STREAK_TS[$ip]" "LAST_COUNT[$ip]"
        fi
    done
}

apply_port_scan_bans() {
    (( SCAN_THRESHOLD > 0 )) || return 0
    local ports ip
    local scanned
    scanned=$(count_distinct_ports_by_peer) || return 0
    while read -r ports ip; do
        [[ -z "$ip" ]] && continue
        is_ip "$ip" || continue
        is_never_ban "$ip" && continue
        is_manual_ban "$ip" && continue
        if (( ports >= SCAN_THRESHOLD )) && ! fw_member "$ip"; then
            ban_ip "$ip" "portscan=$ports"
        fi
    done <<< "$scanned"
}

# =============================================================================
# §10 Ban manager
# =============================================================================
OFFENSE_DIR=""
BAN_HISTORY_FILE=""

offense_of() {
    local f="$OFFENSE_DIR/$1" n
    [[ -f "$f" ]] || { echo 0; return; }
    n=$(cat "$f" 2>/dev/null || echo 0)
    [[ "$n" =~ ^[0-9]+$ ]] || n=0
    echo "$n"
}

offense_bump() {
    local ip=$1 n
    n=$(offense_of "$ip")
    n=$((n + 1))
    mkdir -p "$OFFENSE_DIR"
    printf '%s\n' "$n" > "$OFFENSE_DIR/$ip"
    echo "$n"
}

ttl_for_offense() {
    local offense=$1 ttl=$DEFAULT_TTL i
    for (( i=1; i<offense; i++ )); do
        ttl=$(( ttl * TTL_STEP ))
        (( ttl >= MAX_TTL )) && { ttl=$MAX_TTL; break; }
    done
    echo "$ttl"
}

ban_ip() {
    local ip=$1 reason=$2 offense ttl
    is_ip "$ip" || { log "refusing to ban non-IP: $ip"; return 1; }

    offense=$(offense_bump "$ip")
    ttl=$(ttl_for_offense "$offense")

    if [[ "$DRY_RUN" == "yes" ]]; then
        log "DRY-RUN would ban $ip for ${ttl}s (offense #$offense, reason: $reason)"
        log_json "would_ban" "ip=$ip" "ttl=$ttl" "offense=$offense" "reason=$reason"
        return 0
    fi

    if fw_ban "$ip" "$ttl"; then
        printf '%s %s %s %s %s\n' \
            "$(date -u +%FT%TZ)" "$ip" "$ttl" "$offense" "$reason" \
            >> "$BAN_HISTORY_FILE"
        log "banned $ip for ${ttl}s (offense #$offense, reason: $reason)"
        log_json "ban" "ip=$ip" "ttl=$ttl" "offense=$offense" "reason=$reason"
        notify_enqueue "$ip" "$ttl" "$offense" "$reason"
    else
        log "failed to ban $ip"
        log_json "ban_failed" "ip=$ip"
    fi
}

# =============================================================================
# §11 Notifier
# =============================================================================
NOTIFY_QUEUE=""

notify_init() {
    NOTIFY_QUEUE="$STATE_DIR/notify_queue"
    mkdir -p "$STATE_DIR"
    touch "$NOTIFY_QUEUE"
}

notify_enqueue() {
    local ip=$1 ttl=$2 offense=$3 reason=$4 line
    [[ "$NOTIFY" == "none" ]] && return 0
    line=$(printf '%s|%s|%s|%s|%s' \
        "$(date -u +%FT%TZ)" "$ip" "$ttl" "$offense" "${reason//|/_}")
    if [[ "$NOTIFY" == "per-ip" ]]; then
        local tmp
        tmp=$(mktemp "$STATE_DIR/_notify_oneshot.XXXXXX")
        printf '%s\n' "$line" > "$tmp"
        notify_send_bulk "$tmp"
        rm -f "$tmp"
    else
        printf '%s\n' "$line" >> "$NOTIFY_QUEUE"
    fi
}

notify_send_bulk() {
    local file=$1 count subject body
    [[ -f "$file" ]] || return 0
    count=$(wc -l < "$file" 2>/dev/null || echo 0)
    (( count > 0 )) || return 0
    subject="ddos: $count IP(s) banned"
    body=$(cat "$file")

    if command -v notify-send >/dev/null 2>&1 && [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
        notify-send -u normal "ddos" "$subject" 2>/dev/null || true
    fi
    if command -v mail >/dev/null 2>&1 && [[ -n "$MAIL_TO" ]]; then
        printf '%s\n' "$body" | mail -s "$subject" "$MAIL_TO" 2>/dev/null \
            || log "mail delivery failed"
    fi
    if [[ -n "$WEBHOOK_URL" ]] && command -v curl >/dev/null 2>&1; then
        local payload
        payload=$(printf '{"subject":"%s","count":%d,"body":"%s"}' \
            "$(json_escape "$subject")" "$count" "$(json_escape "$body")")
        curl -fsS -m 10 -H 'Content-Type: application/json' \
            -d "$payload" "$WEBHOOK_URL" >/dev/null 2>&1 \
            || log "webhook delivery failed"
    fi
    log_json "notify_sent" "count=$count"
}

notify_flush_digest() {
    [[ "$NOTIFY" == "digest" ]] || return 0
    [[ -s "$NOTIFY_QUEUE" ]] || return 0
    notify_send_bulk "$NOTIFY_QUEUE"
    : > "$NOTIFY_QUEUE"
}

# =============================================================================
# §12 Signal traps
# =============================================================================
SHUTDOWN=0
RELOAD=0

dump_stats() {
    local c4=0 c6=0
    command -v ipset >/dev/null 2>&1 && {
        c4=$(ipset list "${IPSET_NAME}"  2>/dev/null | grep -c '^[0-9]'    || true)
        c6=$(ipset list "${IPSET_NAME6}" 2>/dev/null | grep -c '^[0-9a-f:]' || true)
    }
    log "stats: banned4=$c4 banned6=$c6 tracked=${#STREAK[@]}"
}

install_traps() {
    trap 'SHUTDOWN=1' TERM INT
    trap 'RELOAD=1'   HUP
    trap 'dump_stats' USR1
}

# =============================================================================
# §13 Subcommands
# =============================================================================
usage() {
    cat <<EOF
$SCRIPT_NAME $SCRIPT_VERSION — connection-count based IP blocker
Author: $SCRIPT_AUTHOR

Usage:
  $SCRIPT_NAME [options] [command]

Commands:
  run           Start the daemon (default)
  once          Run a single sample cycle and exit
  status        Show daemon state, ban counts, and sampler
  list          List currently banned IPs
  unban <ip>    Remove an IP from the ban set and clear its offense count
  test          Show current connections and per-peer counts
  check         Validate config, sampler, and privileges
  install       Install script, config, lists, and systemd unit
  uninstall     Disable unit, remove unit, tear down firewall objects
  teardown      Remove firewall objects only (keep service files)

Options:
  -c, --config <file>   Config file (default: $DEFAULT_CONF)
      --dry-run         Do not modify firewall; log intended actions
  -v, --verbose         Per-cycle tracking output
  -h, --help            This help
      --version         Print version
EOF
}

cmd_status() {
    local c4=0 c6=0 st="stopped" lock="$STATE_DIR/ddos.lock" pid=""
    command -v ipset >/dev/null 2>&1 && {
        c4=$(ipset list "${IPSET_NAME}"  2>/dev/null | grep -c '^[0-9]'    || true)
        c6=$(ipset list "${IPSET_NAME6}" 2>/dev/null | grep -c '^[0-9a-f:]' || true)
    }
    if [[ -f "$lock" ]] && ! flock -n "$lock" true 2>/dev/null; then
        st="running"
        [[ -f "$STATE_DIR/ddos.pid" ]] && pid=$(cat "$STATE_DIR/ddos.pid" 2>/dev/null || true)
    fi
    local sampler
    sampler=$(detect_sampler)
    printf 'ddos %s (author: %s)\n' "$SCRIPT_VERSION" "$SCRIPT_AUTHOR"
    printf '  status:      %s%s\n' "$st" "${pid:+ (pid $pid)}"
    printf '  sampler:     %s\n' "${sampler:-none}"
    printf '  banned4:     %s\n' "$c4"
    printf '  banned6:     %s\n' "$c6"
    printf '  tracked:     %s\n' "${#STREAK[@]}"
    printf '  threshold:   %s connections over %s cycles\n' "$CONN_THRESHOLD" "$PERSIST_CYCLES"
    printf '  interval:    %ss\n' "$SAMPLE_INTERVAL"
    printf '  config:      %s\n' "$CONFIG_FILE"
    printf '  state:       %s\n' "$STATE_DIR"
}

cmd_list() {
    command -v ipset >/dev/null 2>&1 || die "ipset not available"
    ipset list "${IPSET_NAME}"  2>/dev/null | sed -n '/^Members:/,$p' | tail -n +2 || true
    ipset list "${IPSET_NAME6}" 2>/dev/null | sed -n '/^Members:/,$p' | tail -n +2 || true
}

cmd_unban() {
    local ip=${1:-}
    [[ -n "$ip" ]] || die "usage: $SCRIPT_NAME unban <ip>"
    is_ip "$ip" || die "not a valid IP: $ip"
    if fw_unban "$ip"; then
        rm -f "$OFFENSE_DIR/$ip"
        log "unbanned $ip"
        log_json "unban" "ip=$ip"
    else
        log "not banned or invalid: $ip"
        return 1
    fi
}

cmd_test() {
    local sampler
    sampler=$(detect_sampler)
    if [[ -z "$sampler" ]]; then
        log "FAIL: neither ss nor netstat is available"
        return 1
    fi
    log "sampler: $sampler"
    log "sample (first 10 lines):"
    sample_connections_raw | head -n 10
    log "per-peer counts (threshold=$CONN_THRESHOLD, min=$MIN_CONNECTIONS):"
    count_by_peer || true
}

cmd_check() {
    local rc=0
    log "config: $CONFIG_FILE"
    log "  sampler:       $(detect_sampler || echo none)"
    log "  interval:      ${SAMPLE_INTERVAL}s"
    log "  threshold:     $CONN_THRESHOLD conns over $PERSIST_CYCLES cycles"
    log "  states:        $SOCKET_STATES"
    log "  notify:        $NOTIFY"

    [[ -z "$(detect_sampler)" ]] && { log "WARN: no sampler (ss/netstat)"; rc=1; }
    [[ -f "$NEVER_BAN" ]]  && log "OK: whitelist present ($NEVER_BAN)"  || { log "WARN: whitelist missing ($NEVER_BAN)"; rc=1; }
    [[ -f "$MANUAL_BAN" ]] && log "OK: blacklist present ($MANUAL_BAN)" || { log "WARN: blacklist missing ($MANUAL_BAN)"; rc=1; }
    local c
    for c in ipset iptables flock; do
        command -v "$c" >/dev/null 2>&1 && log "OK: $c found" || { log "WARN: $c missing"; rc=1; }
    done
    (( rc == 0 )) && log "check passed" || log "check found issues"
    return $rc
}

write_default_config() {
    cat > "$1" <<'EOF'
# ddos.conf — connection-count based IP blocker
# Format: KEY=value, one per line. '#' starts a comment.
# After edits:  systemctl reload ddos   (SIGHUP)

SAMPLE_INTERVAL=60
CONN_THRESHOLD=100
PERSIST_CYCLES=3
MIN_CONNECTIONS=10
SOCKET_STATES=ESTAB,SYN_RECV
SCAN_THRESHOLD=0
DISTINCT_PORTS_THRESHOLD=20

DEFAULT_TTL=3600
TTL_STEP=2
MAX_TTL=604800

NEVER_BAN=/etc/ddos/ignore.ip.list
MANUAL_BAN=/etc/ddos/block.ip.list
PROTECTED_RANGES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,169.254.0.0/16,::1/128,fe80::/10

IPSET_NAME=ddos4
IPSET_NAME6=ddos6

NOTIFY=digest
DIGEST_MINUTES=15
MAIL_TO=admin@localhost
WEBHOOK_URL=

STATE_DIR=/var/lib/ddos
LOGS_DIR=/var/log/ddos
EOF
}

write_default_ignore() {
    cat > "$1" <<'EOF'
# ignore.ip.list — never-ban ranges. CIDR / IP, one per line.
# 127.0.0.1/32 and ::1/128 are always protected; listed here for clarity.
127.0.0.1/32
::1/128
# Add your management / monitoring / CDN ranges below:
# 203.0.113.0/24    # office VPN
# 198.51.100.0/24   # monitoring
EOF
}

cmd_install() {
    local here
    here=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
    install -d "$DEFAULT_INSTALL_DIR" "/etc/ddos" "$STATE_DIR" "$LOGS_DIR"
    install -m 0755 "$here/ddos.sh" "$DEFAULT_INSTALL_DIR/ddos.sh"
    ln -sf "$DEFAULT_INSTALL_DIR/ddos.sh" "$DEFAULT_BIN_SYMLINK"

    [[ -f "$DEFAULT_CONF" ]] || write_default_config "$DEFAULT_CONF"
    [[ -f "$DEFAULT_NEVER_BAN" ]] || write_default_ignore "$DEFAULT_NEVER_BAN"
    [[ -f "$DEFAULT_MANUAL_BAN" ]] || touch "$DEFAULT_MANUAL_BAN"

    if command -v systemctl >/dev/null 2>&1; then
        cat > /etc/systemd/system/ddos.service <<'UNIT'
[Unit]
Description=ddos — connection-count based IP blocker
Documentation=file:/usr/local/ddos/README.md
After=network-online.target
Wants=network-online.target
ConditionPathExists=/usr/local/ddos/ddos.sh

[Service]
Type=simple
ExecStart=/usr/local/ddos/ddos.sh --config /etc/ddos/ddos.conf run
ExecReload=/bin/kill -HUP $MAINPID
ExecStop=/bin/kill -TERM $MAINPID
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s
User=root
StateDirectory=ddos
RuntimeDirectory=ddos
LogsDirectory=ddos
NoNewPrivileges=no
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=yes
LockPersonality=yes
LimitNOFILE=8192
ReadWritePaths=/var/lib/ddos /var/log/ddos /run/ddos

[Install]
WantedBy=multi-user.target
UNIT
        systemctl daemon-reload
        systemctl enable --now ddos.service
        log "installed and enabled ddos.service"
        log "edit /etc/ddos/ddos.conf, then: systemctl reload ddos"
    else
        log "systemd not found — add to cron:"
        log "  * * * * * root /usr/local/ddos/ddos.sh --config /etc/ddos/ddos.conf once"
    fi
}

cmd_uninstall() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now ddos.service 2>/dev/null || true
        rm -f /etc/systemd/system/ddos.service
        systemctl daemon-reload
    fi
    fw_teardown
    rm -f "$DEFAULT_BIN_SYMLINK"
    log "uninstalled and firewall objects removed (config and script kept)"
}

cmd_teardown() {
    fw_teardown
    log "firewall objects removed (service files kept)"
}

# =============================================================================
# §14 Main loop
# =============================================================================
sample_cycle() {
    CURRENT_TIME=$(date +%s)
    local counts
    if ! counts=$(count_by_peer); then
        log "WARN: cannot sample connections"
        return 1
    fi
    track_cycle "$counts"
    apply_bans_from_streaks
    apply_port_scan_bans
}

cmd_once() {
    fw_init
    load_lists
    sample_cycle
    log "single cycle complete"
}

cmd_run() {
    acquire_lock
    trap 'release_lock' EXIT
    fw_init
    load_lists
    install_traps
    notify_init

    log "started (pid $$, interval=${SAMPLE_INTERVAL}s, threshold=$CONN_THRESHOLD×$PERSIST_CYCLES, dry-run=$DRY_RUN)"
    log_json "start" "interval=$SAMPLE_INTERVAL" "threshold=$CONN_THRESHOLD" "cycles=$PERSIST_CYCLES" "dry_run=$DRY_RUN"

    local last_digest
    last_digest=$(date +%s)

    while (( ! SHUTDOWN )); do
        if (( RELOAD )); then
            log "SIGHUP: reloading config and lists"
            load_config "$CONFIG_FILE"
            validate_config
            load_lists
            RELOAD=0
        fi

        sample_cycle || true

        if [[ "$NOTIFY" == "digest" ]]; then
            local now
            now=$(date +%s)
            if (( now - last_digest >= DIGEST_MINUTES * 60 )); then
                notify_flush_digest
                last_digest=$now
            fi
        fi

        sleep "$SAMPLE_INTERVAL" &
        wait $! 2>/dev/null || true
    done

    notify_flush_digest || true
    log "stopped"
    log_json "stop"
}

# =============================================================================
# Entry point
# =============================================================================
main() {
    while (( $# )); do
        case "$1" in
            -c|--config)  [[ -n "${2:-}" ]] || die "--config requires a path"
                          CONFIG_FILE="$2"; shift 2 ;;
            --dry-run)    DRY_RUN="yes"; shift ;;
            -v|--verbose) VERBOSE="yes"; shift ;;
            -h|--help)    usage; exit 0 ;;
            --version)    echo "$SCRIPT_NAME $SCRIPT_VERSION ($SCRIPT_AUTHOR)"; exit 0 ;;
            run|once|status|list|check|install|uninstall|teardown|test)
                          ACTION="$1"; shift ;;
            unban)        [[ -n "${2:-}" ]] || die "unban requires an IP"
                          ACTION="$1"; ARG1="$2"; shift 2 ;;
            *)            die "unknown argument: $1" ;;
        esac
    done

    load_config "$CONFIG_FILE"
    validate_config

    mkdir -p "$STATE_DIR" "$LOGS_DIR" 2>/dev/null || true
    EVENTS_LOG="$LOGS_DIR/events.jsonl"
    OFFENSE_DIR="$STATE_DIR/offenses"
    BAN_HISTORY_FILE="$STATE_DIR/ban-history"
    mkdir -p "$OFFENSE_DIR" 2>/dev/null || true

    case "$ACTION" in
        run)       cmd_run ;;
        once)      cmd_once ;;
        status)    cmd_status ;;
        list)      cmd_list ;;
        unban)     cmd_unban "$ARG1" ;;
        test)      cmd_test ;;
        check)     cmd_check ;;
        install)   cmd_install ;;
        uninstall) cmd_uninstall ;;
        teardown)  cmd_teardown ;;
        *)         usage; exit 1 ;;
    esac
}

main "$@"
