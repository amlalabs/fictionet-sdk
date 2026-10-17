"""Read complete example world logs."""

import json


def parse_log(text: str) -> list[dict]:
    """Parse the log's JSON Lines, each an object with a string ``type``.

    A malformed line, or a ``lost`` line (the writer's queue overflowed), makes
    the sample unscorable.
    """
    entries = []
    for number, raw in enumerate(text.splitlines(), 1):
        try:
            entry = json.loads(raw)
        except ValueError as error:
            msg = f"invalid world log line {number}; this sample cannot be scored"
            raise RuntimeError(msg) from error
        if not isinstance(entry, dict) or not isinstance(entry.get("type"), str):
            msg = f"world log line {number} is not a typed object; this sample cannot be scored"
            raise RuntimeError(msg)
        if entry["type"] == "lost":
            msg = f"the world lost {entry.get('count')} log lines; this sample cannot be scored"
            raise RuntimeError(msg)
        entries.append(entry)
    return entries


async def read_log(world, log: str, offset: int = 0, *, read_file=None) -> list[dict]:
    """Copy the log to a snapshot, check that the snapshot is read completely, and parse it.

    For final scoring, await finalize_world first: a complete snapshot does not
    prove the live writer has drained. The caller must supply a trusted world
    sandbox and file accessor; this helper does not check sandbox identity.

    Requires world.exec with sh, cp and wc, and a writable log directory. Calls
    for the same log must be serialized because they share log + ".snapshot".
    Read that snapshot through the supplied read_file accessor or world.read_file
    as bytes, checking its byte count and final newline (unless empty).

    Every entry is checked for lost lines before the line offset is applied.
    The offset must be a nonnegative integer no greater than the entry count;
    a shorter snapshot cannot be scored.
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
    entries = parse_log(data.decode())
    if type(offset) is not int or not 0 <= offset <= len(entries):
        msg = f"world log has {len(entries)} entries, invalid offset {offset!r}; this sample cannot be scored"
        raise RuntimeError(msg)
    return entries[offset:]
