#!/usr/bin/env bash
# The scan demo, run inside the VM by cargo xtask demo scan. The scan example's
# office subnet (examples/scan) under Docker Compose: nmap in the agent's
# sandbox finds four simulated hosts and one real container, and the
# dashboard reads the world's collector through its observation socket.
# needs: sdk scan
. "$(dirname "$0")/lib.sh"
host_port="${FICTIONET_DASHBOARD_PORT:-7878}"
seconds="${DASHBOARD_SECONDS:-}"
compose=(docker compose -p fictionet-scan-demo -f /src/examples/scan/compose.yaml
    -f /src/demos/guest/scan.compose.yaml)
AGENT=("${compose[@]}" exec -T scanner)
export SCAN_DASHBOARD_TOKEN_FILE=/run/scan-dashboard-token

cleanup() {
    "${compose[@]}" down -v --remove-orphans -t 1 >/dev/null 2>&1 || true
    rm -f "$SCAN_DASHBOARD_TOKEN_FILE"
}
trap cleanup EXIT
cleanup

step "Build the images and start the world"
note "Six containers: the world (four simulated hosts and a router, with no network at all),"
note "a real container with nginx and OpenSSH behind its own attach at 10.0.0.50, the agent"
note "with nmap behind another attach at 10.0.9.2, and the dashboard."
umask 077
token=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
printf '%s\n' "$token" >"$SCAN_DASHBOARD_TOKEN_FILE"
"${compose[@]}" build --quiet
"${compose[@]}" up -d --wait

step "Open the dashboard"
note "The world's second path opens its observation socket. The dashboard connects to it"
note "with --observation. Its HTTP server listens on the VM's port 7878, forwarded to"
note "127.0.0.1:$host_port on your machine. Open it to watch the scan:"
printf '\n    %shttp://127.0.0.1:%s/#token=%s%s\n\n' "$bold" "$host_port" "$token" "$reset"

step "Host discovery"
note "nmap pings the office subnet from the agent's sandbox. All five hosts answer, the real"
note "container a little later than the simulated ones: its packets cross attach and a kernel."
expect_output 'nmap -sn -n 10.0.0.0/24' 'Nmap scan report for 10\.0\.0\.(10|11|12|13|50)$' '5 hosts up'

step "A SYN scan of the first 1,024 ports, with service detection"
note "A closed port answers with a RST, so nmap reports it closed, not filtered. The real"
note "container's versions come from the real nginx and OpenSSH. The light version probes take"
note "about 40 s, and --max-rate only slows the scan down, so it is easy to follow in the dashboard."
expect_output 'nmap -sS -sV --version-light -n -p 1-1024 --max-rate 300 10.0.0.0/24' \
    '^Nmap scan report for 10\.0\.0\.50' '^22/tcp +open +ssh +OpenSSH' '^80/tcp +open +http +nginx' \
    '^80/tcp +open +http +Apache httpd' '^631/tcp +open +ipp +CUPS' \
    '^Nmap scan report' '^[0-9]+/tcp' '^Not shown' '5 hosts up'

if [[ -z $seconds && -t 0 ]]; then
    note "Opened links keep captured packets within retention limits. Press Enter to finish."
    read -r _
elif [[ -n $seconds ]]; then
    note "Stopping in $seconds s (DASHBOARD_SECONDS sets how long)."
    sleep "$seconds"
fi

step "Clean up"
note "Taking the containers down."
