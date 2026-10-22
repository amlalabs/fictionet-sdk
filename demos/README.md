# Demos

Run `cargo xtask demo` to list the demos. `cargo xtask demo <name>` fetches
the pinned guest files and browser libraries, builds the binary, boots the
VMs and opens the page. The app stays open until Ctrl-C and then powers off
the guests it started.

`cargo xtask demo libraries` downloads the page's browser libraries only.
The terminal uses ghostty-web; the screen uses noVNC. The page and its
libraries are served locally.

## Desktop

`cargo xtask demo desktop` boots an Ubuntu desktop with Firefox, Claude Code
and Codex. Sign in to the coding agents inside the VM. No host credential
is copied into an agent. The world handles their model traffic and answers
supported search tools from its own web.

## Search

`cargo xtask demo search` opens an Ubuntu desktop on the astronomy web.
Firefox, Claude Code and Codex share its pages and search index. Agents sign
in inside the VM and model calls use their own credentials. The World menu
selects Copied, Model-written or Live pages. `OPENROUTER_API_KEY` enables
model-written pages; the world's key is separate from the agents' keys.
`cargo xtask demo search preview` serves the page without a VM.

## Border

`cargo xtask demo border` opens a workstation on its bank. The World menu
changes the route and the impostor's state. The bank login is in `~/.bank`.
Claude Code signs in inside the VM. `cargo xtask demo border preview` serves
the route view with an in-world client and no VM.

## FakeWiki

`cargo xtask demo fakewiki` opens Firefox on Wikipedia. The page's controls
change the article served by the world. `cargo xtask demo fakewiki preview`
serves the page with an in-world reader and no VM.

## Scan

`cargo xtask demo scan` boots a workstation and an office server. Run nmap
from the terminal to inventory the office. `cargo xtask demo scan preview`
uses an in-world scanner without VMs.

## Artifactory

`cargo xtask demo artifactory` opens an internal package index. The world has
no route to public PyPI. Choose the existing `--variant normal`, `missing`,
`lookalike` or `peer` option to select its package inventory. With `peer`,
`--sessions shared` or `separate` selects the colleague's repository state.
`cargo xtask demo artifactory preview` replays the scenario without VMs.

## Page

The world pane opens on Architecture. Packets is the next tab and contains
the flow map, packet list, protocol tree, hex dump and pcapng download.
Selecting a map item filters the packet list. Clearing the selection shows
all declared hosts again. Administrative attachments are excluded from
these views.

Architecture receives service declarations from the world. Its counters,
event lines and pulses come from real observations. The model gateway's
`model.tool` event includes the query and `source: world`; searches answered
there do not count as outside traffic. Model calls and sign-in connections
have separate observations.

The page binds to loopback and uses a bearer capability, exact Host and
Origin validation, and short-lived single-use console tickets. The Screen
and Terminal reach guests through the kit's SSH connection. The admin jump
host carries those sessions and is omitted from the page.

## Development

Run `cargo test --workspace`, the Node tests under `dashboard/` and
`demos/search/app/src/page/`, and the Python package's tests. Demo launches are
interactive applications.

The shared kit handles guests, provisioning, networking and run lifetime.
`Kit::page` declares hosts and panels. `Kit::world` starts the world's
services. `Guest::forbid` adds words that must not appear in guest files,
names, packages or commands. The kit's containment panel reports observed
network probes.

For a series of VM integration runs, use `cargo xtask vm up` first and
`cargo xtask vm down` when finished. A demo shuts down a VM it started.
