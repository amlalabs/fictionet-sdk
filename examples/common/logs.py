"""Read complete snapshots of example world logs."""

import json


async def read_log(world, log: str, offset: int = 0) -> list[dict]:
    """Check the snapshot byte count and all lines before applying the offset."""
    snapshot = log + ".snapshot"
    r = await world.exec(
        ["sh", "-c", 'cp "$1" "$2" && wc -c < "$2"', "copy", log, snapshot]
    )
    if not r.success:
        msg = f"cannot read world log: {r.stderr}"
        raise RuntimeError(msg)
    want = int(r.stdout)
    data = await world.read_file(snapshot, text=False)
    if len(data) != want or (data and not data.endswith(b"\n")):
        msg = f"read {len(data)} of the log's {want} bytes; this sample cannot be scored"
        raise RuntimeError(msg)
    lines = [ln for ln in data.decode().splitlines() if ln.strip()]
    entries = [json.loads(ln) for ln in lines]
    if any(entry.get("type") == "lost" for entry in entries):
        msg = "the world lost log lines; this sample cannot be scored"
        raise RuntimeError(msg)
    return entries[offset:]
