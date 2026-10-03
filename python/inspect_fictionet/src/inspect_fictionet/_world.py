"""Reading the world's files from a scorer."""

from inspect_ai.util import sandbox


async def read_world_file(path: str, *, text: bool = True) -> str | bytes:
    """Reads a file from the world's container, such as a log the world
    writes of what the agent did.

    Call it from a scorer, after the agent has finished. It is
    `sandbox("world").read_file(path)`, with one check first: that the
    sample really has a sandbox named `world`. Inspect's `sandbox(name)`
    returns the default sandbox, the agent's, when a sample has only one
    sandbox, and then the agent could write the file this reads.

    The docker backend has the sandbox `world`. inspect_k8s_sandbox makes
    one sandbox per pod, the agent's container, so on Kubernetes this
    raises `RuntimeError`.
    """
    world = sandbox("world")
    if world is sandbox():
        raise RuntimeError(
            "this sample has no sandbox named 'world', only the agent's; refusing to read "
            f"{path} there. On Kubernetes, the world's container is not an Inspect sandbox."
        )
    return await world.read_file(path, text=text)
