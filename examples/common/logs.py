"""Read complete example world logs."""

import json


async def read_log(world, log: str, offset: int = 0, *, raw: bool = False, read_file=None) -> list[dict] | bytes:
    """Read a complete log, returning raw bytes or entries after a line offset.

    Finalize before scoring. Preflight reads fail if the byte count changes.
    A supplied read_file accessor reads from the same private world.
    """
    r = await world.exec(["stat", "-c", "%s", log])
    if not r.success:
        msg = f"cannot read world log: {r.stderr}"
        raise RuntimeError(msg)
    want = int(r.stdout)
    data = await (read_file or world.read_file)(log, text=False)
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
