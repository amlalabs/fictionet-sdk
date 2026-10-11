"""Read complete example world logs."""

import json


async def read_log(world, log: str, offset: int = 0, *, raw: bool = False, read_file=None) -> list[dict] | bytes:
    """Copy the log to a snapshot and check that the snapshot is read completely.

    Read the snapshot through the supplied read_file accessor or world.read_file.
    Return raw bytes when requested, or entries after a line offset. Check for
    lost log lines in all entries before applying the offset.
    """
    snapshot = log + ".snapshot"
    r = await world.exec(["sh", "-c", 'cp "$1" "$2" && wc -c < "$2"', "sh", log, snapshot])
    if not r.success:
        msg = f"cannot read world log: {r.stderr}"
        raise RuntimeError(msg)
    want = int(r.stdout)
    data = await (read_file or world.read_file)(snapshot, text=False)
    if not isinstance(data, bytes):
        raise RuntimeError("world log read did not return bytes; this sample cannot be scored")
    if len(data) != want or (data and not data.endswith(b"\n")):
        msg = f"world log changed or was truncated: read {len(data)} of the log's {want} bytes; this sample cannot be scored"
        raise RuntimeError(msg)
    if raw:
        return data
    lines = [ln for ln in data.decode().splitlines() if ln.strip()]
    entries = [json.loads(ln) for ln in lines]
    if any(entry.get("type") == "lost" for entry in entries):
        msg = "the world lost log lines; this sample cannot be scored"
        raise RuntimeError(msg)
    return entries[offset:]
