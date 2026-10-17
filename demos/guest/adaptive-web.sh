#!/usr/bin/env bash
# The adaptive web demo, run inside the VM by cargo xtask demo adaptive-web. The
# adaptive web (examples/adaptive-web) under Docker Compose with its stub
# generator and no model: a web search, the pages behind the results, made
# from a seed the first time they are asked for, and the world's log.
# needs: sdk adaptive-web
. "$(dirname "$0")/lib.sh"
compose=(docker compose -p fictionet-adaptive-web-demo -f /src/examples/adaptive-web/compose.yaml
    -f /src/demos/guest/adaptive-web.compose.yaml)
AGENT=("${compose[@]}" exec -T default)
export ADAPTIVE_WEB_SEED=corvane-acquisition ADAPTIVE_WEB_GENERATOR=stub
search='https://www.google.com/search?q=Corvane+Therapeutics+acquisition'
# The result links on the search page, one URL per line.
links="curl -fsS '$search' | grep -o 'yuRUbf\"><a href=\"[^\"]*' | sed 's/.*href=\"//'"

cleanup() { "${compose[@]}" down -v --remove-orphans -t 1 >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

step "Build the images and start the world"
note "Three containers: the world (web::Sites in Rust for any name, and the Python backend that"
note "makes and keeps the pages, with no network at all), attach, and the agent, a box with curl"
note "that trusts the world's CA. The seed is $ADAPTIVE_WEB_SEED. The stub generator needs no key."
"${compose[@]}" build --quiet
"${compose[@]}" up -d --wait

step "A web search"
note "Any public name resolves, and any URL has a page. The search engine answers with ten"
note "results, made for this query the first time it is asked. Here are their titles and links:"
expect_output "curl -fsS '$search' | grep -o '<h3>[^<]*' | sed 's/<h3>//' | head -5" '.'
expect_output "$links | head -5" '^https://'

step "The page behind the first result"
note "The page is made now and kept, so the same URL returns the same page from here on:"
url="$("${AGENT[@]}" bash -c "$links | head -1")"
agent "curl -fsS '$url' | sed 's/<[^>]*>/ /g' | tr -s ' \n' ' ' | cut -c1-600; echo"
agent "curl -fsS -o /dev/null -w '%{http_code} in %{time_total} s the second time\n' '$url'"

step "The world's log"
note "Every name looked up and every request, with the site's reason for existing:"
"${compose[@]}" exec -T world cat /var/lib/fictionet/log.jsonl |
    jq -c 'select(.type == "site" or .type == "http") | {type, host, path, why} | with_entries(select(.value != null))' |
    sed 's/^/    /'

step "Clean up"
note "Taking the containers down."
