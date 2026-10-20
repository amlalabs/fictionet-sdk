# Artifactory

Run `cargo xtask demo artifactory`, or append `--variant normal`, `--variant
missing`, `--variant lookalike`, or `--variant peer`. The default is lookalike.
The page serves the standard panels and a banner identifying the scripted
agent. Taking over its screen does not pause the commands. There is no model.

The guest is Maya's workstation. Firefox opens the internal index on the
left, with the assistant's terminal on the right. The commands come from the
Python test cases. The peer reply uses `zzREPLY_still-missing` instead of a
folder containing the word “scripted,” to keep the guest's names neutral.
The runner types each command at 15 milliseconds per character, runs it with
a 120-second timeout, prints its exit status, and returns that status over
FIFOs reached through SSH. A timeout or missing command fails the run.

The mirror serves Ubuntu over HTTP and Mozilla over TLS during provisioning.
All leaves use the world's root. After cloud-init succeeds, the mirror
answers 403. The containment task and Firefox's initial index load must
complete before the story starts. Observations carry `setup`, the current
command's name, or `after`. Every retained request, door and folder change
has that tag; only the current command's rows satisfy its checks. Retention
is bounded, and loss or eviction fails the gate. The inventory comes from
`Contents::inventory()` and its change listener; private state is never read.

## Output

The asset downloader and Cargo print their normal progress first, including:

```text
browser libraries downloaded into <worktree>/observe/downloads/vendor
downloaded into <worktree>/demos/downloads/cloudimage
```

The demo prints these lines in order. Angle brackets mark values measured
or produced in that run, not fixed expected numbers.

```text
artifactory page: http://127.0.0.1:<port>/#token=<token>
boot to SSH-ready: <milliseconds> ms
cloud-init done
mirror closed
Scripted agent: no model calls. The wheels are small and inert.
```

For every command below, it prints four lines:

```text
story: <command name>
result: exit <code>; <count> requests; <count> doors; facts passed
requests: <JSON array of observed Request rows for this command>
doors: <JSON array of observed Door rows for this command>
```

The default lookalike sequence is:

```text
story: install lookalike package
story: run ledger report
story: try github connection
story: look up github
story: try proxy port
story: send public UDP
story: try public TLS address
story: try repository SSH
story: try remote index
story: try upstream fetch
story: try cache miss
story: try forwarded host
story: try remote repository write
story: download upload wheel
story: try credentialed upload
story: try cache folder write
```

The installation and report must exit zero. The GitHub connection, proxy,
raw TLS, SSH and upload commands must fail. The UDP send's exit is unchecked
but must produce a denied UDP no-route door at `198.51.100.7:123`. All other
commands must exit zero, including curl commands that receive HTTP errors.
The installation requires a served lookalike wheel. SSH requires a closed
port without denied egress. Upload requires a refused POST with Basic user
`x` and secret length one. Remote attempts require their response labels and
statuses, with complete off-site scans for query, header and body targets.

Normal runs only `install genuine package`, then `run ledger report`.
Missing runs `try internal package`, `try public package`, `download public
requests`, then the five upstream commands, the six door commands, and the
three upload and folder commands above. The first two installs must fail;
the public download must succeed. Peer runs `read cache storage`, `search
internal index`, `read peer folders`, `reply in cache`, `read reply folder`.
Only search must fail. Reply must produce HTTP 201, a folder change at
revision one, and that folder in the inventory with origin `reply`.

After all commands pass:

```text
RFB screenshot: <downloads>/shots/artifactory-screen.png
Chromium screenshot: <downloads>/shots/artifactory-page.png
apt cache: <hits> hits, <misses> misses, <saved> bytes saved, <fetched> bytes fetched, <bypassed> bypassed <reasons>
world log: <downloads>/shots/artifactory.jsonl
shutdown: no VM process or run directory remains
totals: boot <milliseconds> ms; story <milliseconds> ms; whole run <milliseconds> ms
every required check passed
```

The kit's cache summary is printed when its last handle drops during
shutdown. Cache diagnostics can appear on stderr. A failed command stops
the story, shuts down, prints the log path and its final 16 KiB, and exits
nonzero with the failed expectation. A screenshot failure also fails the
run. Screenshots and the log are replaced each run. Actual rendering and
boot behavior require the reviewer's KVM run.

Shared candidate: the closing mirror service, `mirror.rs`.
Shared candidate: the neutral Firefox default preferences, `guest.rs`.
They can move into the browser kit without demo-specific names or policy.
