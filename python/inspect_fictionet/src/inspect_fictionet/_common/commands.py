"""Checked command outcomes for example probes. Load with runpy.run_path.

These helpers classify command results, not the trustworthiness of their source.
Agent-writable diagnostics alone cannot prove isolation. Callers must choose a
trusted runner and the expected outcome for each probe. SUCCESS means rc == 0;
callers still check content. EXPECTED_FAILURE is a recognized denial, not a
blanket acceptance of nonzero status. INVALID_OBSERVATION never passes a check.
"""

from dataclasses import dataclass
from enum import Enum
import re
import subprocess


CURL_DIRECT = ("curl", "-q", "--noproxy", "*")
"""Curl prefix that ignores curlrc and bypasses proxies. Keep -q first."""

CURL_CONNECT_WRITE_OUT = "%{remote_ip}\t%{num_connects}\t%{time_connect}\n"
"""Use with curl -o /dev/null -w; num_connects detects stalled TLS handshakes."""


class Outcome(str, Enum):
    """Execution, recognized denial, connection failure, or unusable evidence."""

    SUCCESS = "success"
    EXPECTED_FAILURE = "expected_failure"
    CONNECTED_THEN_FAILED = "connected_then_failed"
    INVALID_OBSERVATION = "invalid_observation"


@dataclass(frozen=True)
class Result:
    """One command's immutable argv, return code, and unmodified text streams."""

    argv: tuple[str, ...]
    rc: int
    stdout: str
    stderr: str

    def __post_init__(self):
        object.__setattr__(self, "argv", tuple(self.argv))


def run(argv, *, runner=subprocess.run, **kwargs) -> Result:
    """Run one command through subprocess.run or an injected equivalent.

    Missing tools, timeouts and interrupts propagate. A completed nonzero
    command remains a Result so its diagnostic can be classified and reported.
    """
    argv = tuple(argv)
    result = runner(list(argv), capture_output=True, text=True, check=False, **kwargs)
    return Result(argv, result.returncode, result.stdout, result.stderr)


async def run_async(argv, *, runner, **kwargs) -> Result:
    """Run one command through an injected async runner such as sandbox().exec.

    The returned object must have returncode, stdout and stderr. No Inspect
    import is needed. Exceptions propagate just as they do in run.
    """
    argv = tuple(argv)
    result = await runner(list(argv), **kwargs)
    return Result(argv, result.returncode, result.stdout, result.stderr)


def _invalid(result: Result, *, allow_silent=False) -> bool:
    return (
        not result.argv
        or any(not isinstance(arg, str) for arg in result.argv)
        or type(result.rc) is not int
        or result.rc < 0
        or result.rc in (126, 127)
        or not isinstance(result.stdout, str)
        or not isinstance(result.stderr, str)
        or (not allow_silent and result.rc != 0 and not (result.stdout.strip() or result.stderr.strip()))
    )


def classify(result: Result) -> Outcome:
    """Check execution of an ordinary diagnostic; nonzero is not absence."""
    if _invalid(result) or result.rc != 0:
        return Outcome.INVALID_OBSERVATION
    return Outcome.SUCCESS


def succeeded(result: Result, *, stdout: str | None = None) -> bool:
    """Require rc 0 and, when supplied, the exact stdout, including whitespace.

    Curl's -w HTTP status is usable only after this status check. A completed
    404 is valid evidence; a partial 200 or 404 is not. Do not use curl -f for
    control paths whose expected HTTP status is non-200.
    """
    return classify(result) == Outcome.SUCCESS and (stdout is None or result.stdout == stdout)


def classify_curl(result: Result) -> Outcome:
    """Separate a completed transfer, pre-connect denial, and later failure.

    For rc 28, denial requires CURL_CONNECT_WRITE_OUT with no connections,
    no remote address and zero connection time. Any connection evidence or
    post-connect timeout text takes precedence. Timeout text alone cannot
    distinguish denial from a stalled TLS handshake, whose connection time
    can also be zero. HTTP -w text is never success on nonzero rc.

    A TLS error may be expected for a world IP or a rejected SNI name. It is
    not pre-connect containment of an outside address. Callers must check the
    expected class, rc and diagnostic for that specific probe.
    """
    if _invalid(result):
        return Outcome.INVALID_OBSERVATION
    if result.rc == 0:
        return Outcome.SUCCESS
    if result.rc in (6, 7):
        return Outcome.EXPECTED_FAILURE
    if result.rc in (18, 35, 52, 56, 60):
        return Outcome.CONNECTED_THEN_FAILED
    if result.rc != 28:
        return Outcome.INVALID_OBSERVATION
    if "Operation timed out" in result.stderr or "bytes received" in result.stderr:
        return Outcome.CONNECTED_THEN_FAILED
    timing = re.fullmatch(r"([^\s]*)\t(0|[1-9][0-9]*)\t([0-9]+\.[0-9]+)\n", result.stdout)
    if not timing:
        return Outcome.INVALID_OBSERVATION
    remote_ip, num_connects, time_connect = timing.groups()
    if remote_ip or num_connects != "0" or any(digit not in "0." for digit in time_connect):
        return Outcome.CONNECTED_THEN_FAILED
    return Outcome.EXPECTED_FAILURE


def classify_dig(result: Result) -> Outcome:
    """Recognize dig's no-server response; other failures are inconclusive."""
    if _invalid(result):
        return Outcome.INVALID_OBSERVATION
    if result.rc == 9 and any(
        "no servers could be reached" in text for text in (result.stdout, result.stderr)
    ):
        return Outcome.EXPECTED_FAILURE
    return classify(result)


def classify_getent(result: Result) -> Outcome:
    """Recognize getent's unresolved lookup (rc 2), which can be silent.

    Require a getent executable, database and key. Any stdout on rc 2 means
    some keys may have resolved, so the observation cannot establish denial.
    """
    if _invalid(result, allow_silent=result.rc == 2):
        return Outcome.INVALID_OBSERVATION
    if result.rc == 2:
        if (len(result.argv) < 3 or result.argv[0].rsplit("/", 1)[-1] != "getent"
                or result.stdout):
            return Outcome.INVALID_OBSERVATION
        return Outcome.EXPECTED_FAILURE
    return classify(result)


def classify_connect(result: Result) -> Outcome:
    """Classify a Python socket probe that prints CONNECTED after connecting.

    A nonzero probe needs an OSError or TimeoutError traceback to show denial.
    A CONNECTED line takes precedence over any later exception.
    """
    if _invalid(result):
        return Outcome.INVALID_OBSERVATION
    if "CONNECTED" in result.stdout.splitlines():
        return Outcome.SUCCESS if result.rc == 0 else Outcome.CONNECTED_THEN_FAILED
    if (result.rc != 0 and "Traceback (most recent call last):" in result.stderr
            and re.search(r"^(OSError|TimeoutError):[^\n]*\n?\Z", result.stderr, re.M)):
        return Outcome.EXPECTED_FAILURE
    return Outcome.INVALID_OBSERVATION


def classify_ip_add(result: Result) -> Outcome:
    """Recognize permission denial for ip addr/route add, not missing routes."""
    if _invalid(result):
        return Outcome.INVALID_OBSERVATION
    if (result.rc == 2 and "Operation not permitted" in result.stderr
            and "No such process" not in result.stderr):
        return Outcome.EXPECTED_FAILURE
    return classify(result)


def path_absent(result: Result) -> bool:
    """Require one ls -ld path to report absence. Keep its raw Result to report.

    A listing or permission denial cannot establish absence. A combined ls
    result is invalid even when one of its paths is missing.
    """
    return (
        not _invalid(result)
        and len(result.argv) == 3 and result.argv[:2] == ("ls", "-ld")
        and result.rc != 0 and not result.stdout.strip()
        and "No such file or directory" in result.stderr
        and "Permission denied" not in result.stderr
    )


async def inspect_paths(paths, *, runner, **kwargs) -> tuple[Result, ...]:
    """Inspect every requested private path independently through an async runner.

    Check path_absent on every result. Reject an empty inventory so it cannot
    produce a vacuous pass. A runner exception aborts inspection.
    """
    paths = tuple(paths)
    if not paths:
        raise ValueError("private path inventory is empty")
    results = []
    for path in paths:
        results.append(await run_async(["ls", "-ld", path], runner=runner, **kwargs))
    return tuple(results)


def read_env(result: Result) -> dict[str, str]:
    """Read a successful env diagnostic. Reject malformed or ambiguous entries."""
    if not succeeded(result):
        raise RuntimeError(f"env observation failed (rc={result.rc}): {result.stderr}")
    variables = {}
    for line in result.stdout.splitlines():
        name, separator, value = line.partition("=")
        if not separator or not name or name in variables:
            raise RuntimeError("env observation has malformed or duplicate entries")
        variables[name] = value
    return variables


def require_no_proxy(result: Result) -> None:
    """Require a successful env read with no variable named *_proxy, in any case."""
    proxies = [name for name in read_env(result) if name.lower().endswith("_proxy")]
    if proxies:
        raise RuntimeError("proxy environment variables are present: " + ", ".join(proxies))
