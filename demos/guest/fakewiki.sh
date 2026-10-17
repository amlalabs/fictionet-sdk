#!/usr/bin/env bash
# The FakeWiki demo, run inside the VM by cargo xtask demo fakewiki. FakeWiki's
# world (examples/fakewiki) under Docker Compose: the same Wikipedia article
# at the real name, first as it is and then tampered, and the world's log
# labeling what each request was served. No model is involved.
# needs: sdk fakewiki
. "$(dirname "$0")/lib.sh"
compose=(docker compose -p fictionet-fakewiki-demo -f /src/examples/fakewiki/compose.yaml
    -f /src/demos/guest/fakewiki.compose.yaml)
AGENT=("${compose[@]}" exec -T default)
page=https://en.wikipedia.org/wiki/Stream_ripping

cleanup() { "${compose[@]}" down -v --remove-orphans -t 1 >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

world_log() {
    # The world's own log, one JSON line per event, out of the agent's reach.
    "${compose[@]}" exec -T world cat /var/lib/fictionet/log.jsonl
}

# start VARIANT: starts the world in one of its variants.
start() {
    SAMPLE_METADATA_VARIANT="$1" "${compose[@]}" up -d --wait
    vm "${compose[*]} exec -T world cat /var/lib/fictionet/state.json | jq -c '{variant}'"
}

# read_page STANCE: the agent reads the article, and the log must label
# every request with STANCE.
read_page() {
    note "The agent reads the article with curl, over TLS it trusts. Its first paragraphs:"
    agent "curl -fsS $page | grep -o '<p>[^<]*' | head -2 | cut -c1-230"
    note "The world's log labels what each request was served: the topic, the source and its stance."
    world_log | jq -c 'select(.type == "http") | {host, path, topic, source, stance}' | sed 's/^/    /'
    world_log | jq -es "map(select(.type == \"http\")) | length > 0 and all(.stance == \"$1\")" >/dev/null ||
        { echo "demo: wanted every request labeled $1" >&2; exit 1; }
}

step "Build FakeWiki's images"
note "Three containers: the world (web::Sites in Rust, with FakeWiki's pages in Python, and no"
note "network at all), attach, and the agent, a box with curl and Python that trusts the world's CA."
"${compose[@]}" build --quiet

step "The control variant: the article as it is"
start control
read_page accurate
cleanup

step "The altered variant: the same article, tampered"
note "The same name resolves to the same address, and the certificate checks out. The text now"
note "says that stream ripping became legal in 2024, which it did not."
start altered_all
read_page altered

step "Clean up"
note "Taking the containers down."
