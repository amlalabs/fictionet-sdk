# Shared transfer checks for Docker and Kubernetes tests.
# Return a single transfer's measurement, or a diagnostic on failure.
# Upload responses may put the byte count and measurement on separate lines.
check_transfer() {
    local bytes="$1"
    shift
    local out size value extra
    if ! out="$("$@")"; then
        echo "transfer failed: $out"
        return 1
    fi
    if read -r size value extra <<<"${out//$'\n'/ }" && [[ $size == "$bytes" &&
        $value =~ ^[0-9]+([.][0-9]+)?$ && -z $extra ]]; then
        echo "$value"
    else
        echo "expected $bytes bytes and one measurement, got: $out"
        return 1
    fi
}

# Commands print one "bytes seconds" row per download and must fail on errors.
# A zero maximum or spread disables that timing threshold.
check_downloads() {
    local name="$1" count="$2" max="$3" spread="$4"
    shift 4
    local out times
    if ! out="$("$@")"; then
        fail "$name: transfer failed: $out"
        return
    fi
    if ! awk -v count="$count" '
        NF != 2 || $1 != 16777216 || $2 !~ /^[0-9]+([.][0-9]+)?$/ { bad = 1 }
        END { exit (bad || NR != count) }
    ' <<<"$out"; then
        fail "$name: expected $count complete 16 MiB downloads: $out"
        return
    fi
    read -r -a times <<<"$(awk '{print $2}' <<<"$out" | sort -n | tr '\n' ' ')"
    if [[ ${FICTIONET_PERF_CHECK:-0} == 1 ]] && ! awk \
        -v a="${times[0]}" -v b="${times[-1]}" -v max="$max" -v spread="$spread" '
        BEGIN { exit !((max == 0 || b < max) && (spread == 0 || sprintf("%.2f", b - a) + 0 < spread)) }
    '; then
        fail "$name: timing threshold exceeded (${times[0]} s to ${times[-1]} s; max=$max s, spread=$spread s; 0 disables a threshold)"
    else
        pass "$name (${times[0]} s to ${times[-1]} s)"
    fi
}

check_recovery() {
    local before="$1" after="$2"
    [[ $before != failed && $after != failed ]] || return 1
    [[ ${FICTIONET_PERF_CHECK:-0} != 1 ]] ||
        awk -v a="$after" -v f="$before" 'BEGIN { exit !(a < 2 * f + 0.1) }'
}

# The holder prints one readiness line and keeps its sockets until released.
# Save $! because Bash may unset holder_PID when it reaps an early exit.
start_holder() {
    local variable="$1"
    shift
    coproc holder { "$@"; }
    holder_pid=$!
    read_holder "$variable"
}

read_holder() {
    local -n readiness="$1"
    local fd=${holder[0]:-}
    readiness='0 0'
    if [[ -n $fd ]] && read -r -t 120 -u "$fd" readiness 2>/dev/null; then
        return 0
    fi
    readiness='0 0'
    return 1
}

release_holder() {
    local fd=${holder[1]:-} status=0
    # A closed pipe must not terminate the parent shell or print fd errors.
    if [[ -n $fd ]]; then
        { (printf 'release\n'); } 2>/dev/null >&"$fd" || status=1
    else
        status=1
    fi
    if [[ -n ${holder_pid:-} ]]; then
        wait "$holder_pid" || status=1
    else
        status=1
    fi
    return "$status"
}

# Run inside the agent after releasing a holder. FIN_WAIT and CLOSE_WAIT
# still count against the world's limit; give them 10 s to finish closing.
drain_connections() {
    "$@" bash -c '
        for ((i=0; i<100; i++)); do
            remaining=$(awk '\''$3 == "010012C6:0050" && $4 != "06" { n++ }
                END { print n+0 }'\'' /proc/net/tcp) || exit 1
            [[ $remaining == 0 ]] && exit 0
            sleep 0.1
        done
        echo "$remaining connections to 198.18.0.1:80 did not close within 10 s" >&2
        exit 1'
}
