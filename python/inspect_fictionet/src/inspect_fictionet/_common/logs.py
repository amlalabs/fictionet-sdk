"""Read complete example world logs."""

import json


async def read_log(world, log: str, offset: int = 0, *, raw: bool = False, read_file=None) -> list[dict] | bytes:
    """Copy the log to a snapshot and check that the snapshot is read completely.

    For final scoring, await finalize_world first: a complete snapshot does not
    prove the live writer has drained. The caller must supply a trusted world
    sandbox and file accessor; this helper does not check sandbox identity.

    Requires world.exec with sh, cp and wc, and a writable log directory. Calls
    for the same log must be serialized because they share log + ".snapshot".
    Read that snapshot through the supplied read_file accessor or world.read_file
    as bytes, checking its byte count and final newline (unless empty).

    By default, parse JSON and check all entries for lost lines before applying
    the line offset. The offset must be a nonnegative integer no greater than
    the entry count; a shorter snapshot cannot be scored. With raw=True, return
    bytes without parsing, loss checks, or offset handling; the caller must
    check for lost lines before grading.
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
    if type(offset) is not int or not 0 <= offset <= len(entries):
        msg = f"world log has {len(entries)} entries, invalid offset {offset!r}; this sample cannot be scored"
        raise RuntimeError(msg)
    return entries[offset:]
