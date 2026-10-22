"""Image builds: the compose entry for an image or a `Build`, and the
Dockerfile written for a `CargoExample`."""

from __future__ import annotations

import errno
import hashlib
import os
import posixpath
import re
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any

from ._config import Build, CargoExample
from ._files import _short_key, _write_atomic, _write_once


def _image_or_build(image: str | Build | CargoExample, role: str, cache: Path) -> dict[str, Any]:
    if isinstance(image, str):
        return {"image": image}
    if isinstance(image, CargoExample):
        image = _cargo_build(image, cache)
    dockerfile = Path(image.dockerfile).resolve()
    if not dockerfile.is_file():
        raise FileNotFoundError(f"{role}: no Dockerfile at {dockerfile}")
    context = Path(image.context).resolve() if image.context is not None else dockerfile.parent
    build: dict[str, Any] = {"context": str(context), "dockerfile": str(dockerfile)}
    if image.target:
        build["target"] = image.target
    if image.args:
        build["args"] = dict(image.args)
    # The tag follows the original configuration; only the context and compose
    # paths change on source edits, so rebuilding replaces the tagged image.
    tag = f"inspect-fictionet-{role}:{_short_key(repr(sorted(build.items())))}"
    build["context"] = str(_snapshot_context(context, dockerfile, cache))
    return {"build": build, "image": tag}


def _ignore_pattern(pattern: str) -> re.Pattern[str]:
    """Docker's root-anchored filepath.Match syntax, with its ** extension."""
    # Docker optimizes a leading ** followed only by literal text as a suffix.
    if pattern.startswith("**") and not any(c in pattern[2:] for c in "*?[]\\"):
        suffix = pattern[2:]
        expression = r"[\s\S]*" + re.escape(suffix)
        if suffix.startswith("/"):
            expression += "|" + re.escape(suffix[1:])
        return re.compile(expression)
    if pattern.endswith("**") and not any(c in pattern[:-2] for c in "*?[]\\"):
        return re.compile(re.escape(pattern[:-2]) + r"[\s\S]*")
    expression = ""
    i = 0
    while i < len(pattern):
        c = pattern[i]
        i += 1
        if c == "*":
            if i < len(pattern) and pattern[i] == "*":
                i += 1
                if i < len(pattern) and pattern[i] == "/":
                    i += 1
                expression += ".*" if i == len(pattern) else "(?:.*/)?"
            else:
                expression += "[^/]*"
        elif c == "?":
            expression += "[^/]"
        elif c == "\\":
            if i == len(pattern):
                raise ValueError(f"invalid Docker ignore pattern: {pattern!r}")
            expression += re.escape(pattern[i])
            i += 1
        elif c == "[":
            group = ""
            if i < len(pattern) and pattern[i] == "^":
                group = "^"
                i += 1
            start = i
            while i < len(pattern) and pattern[i] != "]":
                # Go permits ranges and backslash escapes, but not a bare '-'.
                def char() -> str:
                    nonlocal i
                    if i == len(pattern) or pattern[i] in "-]":
                        raise ValueError(f"invalid Docker ignore pattern: {pattern!r}")
                    if pattern[i] == "\\":
                        i += 1
                        if i == len(pattern):
                            raise ValueError(f"invalid Docker ignore pattern: {pattern!r}")
                    value = re.escape(pattern[i])
                    i += 1
                    return value

                group += char()
                if i < len(pattern) and pattern[i] == "-":
                    i += 1
                    group += "-" + char()
            if i == start or i == len(pattern):
                raise ValueError(f"invalid Docker ignore pattern: {pattern!r}")
            expression += "[" + group + "]"
            i += 1
        else:
            expression += re.escape(c)
    try:
        return re.compile(expression)
    except re.error as e:
        raise ValueError(f"invalid Docker ignore pattern: {pattern!r}") from e


class _DockerIgnore:
    def __init__(self, text: str):
        self.patterns = []
        for line in text.removeprefix("\ufeff").splitlines():
            if line.startswith("#") or not line.strip():
                continue
            pattern = line.strip()
            exception = pattern.startswith("!")
            if exception:
                pattern = pattern[1:].strip()
                if not pattern:
                    raise ValueError("invalid Docker ignore pattern: '!'")
            pattern = posixpath.normpath(pattern).lstrip("/")
            if pattern != ".":
                self.patterns.append((_ignore_pattern(pattern), exception))
        self.exceptions = any(exception for _, exception in self.patterns)

    def excludes(self, path: Path) -> bool:
        names = [path.as_posix(), *(p.as_posix() for p in path.parents if p != Path("."))]
        excluded = False
        for pattern, exception in self.patterns:
            if exception == excluded and any(pattern.fullmatch(name) for name in names):
                excluded = not exception
        return excluded


def _context_paths(context: Path, ignore: _DockerIgnore) -> list[Path]:
    paths = {Path(".")}

    def visit(directory: Path):
        for path in sorted(directory.iterdir()):
            relative = path.relative_to(context)
            excluded = ignore.excludes(relative)
            if not excluded or relative == Path(".dockerignore"):
                paths.update((relative, *relative.parents))
            if (not excluded or ignore.exceptions) and not path.is_symlink() and path.is_dir():
                visit(path)

    visit(context)
    return sorted(paths)


def _context_hash(context: Path, paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for relative in paths:
        path = context / relative
        mode = path.lstat().st_mode
        for value in (os.fsencode(relative.as_posix()), str(mode).encode()):
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)
        if stat.S_ISLNK(mode):
            target = os.fsencode(os.readlink(path))
            digest.update(len(target).to_bytes(8, "big"))
            digest.update(target)
        elif stat.S_ISREG(mode):
            with path.open("rb") as f:
                digest.update(hashlib.file_digest(f, "sha256").digest())
        elif not stat.S_ISDIR(mode):
            raise ValueError(f"unsupported build context file: {path}")
    return digest.hexdigest()


def _snapshot_context(context: Path, dockerfile: Path, cache: Path) -> Path:
    ignore_file = dockerfile.with_name(dockerfile.name + ".dockerignore")
    if not ignore_file.is_file():
        ignore_file = context / ".dockerignore"
    ignore = _DockerIgnore(ignore_file.read_text() if ignore_file.is_file() else "")
    cache_relative = cache.relative_to(context) if cache.is_relative_to(context) else None
    cache_error = (
        f"cache_dir {cache} would be included in build context {context}; "
        "move cache_dir out of the context, or exclude it and everything under it "
        "in the effective ignore rules"
    )
    if cache_relative is not None and (cache_relative == Path(".") or not ignore.excludes(cache_relative)):
        raise ValueError(cache_error)
    paths = _context_paths(context, ignore)
    # Ignore exceptions can re-include descendants, which also includes their parents.
    if cache_relative in paths:
        raise ValueError(cache_error)
    directory = cache / "context"
    # Read contents on every call: a stat-keyed hash cache would miss the same
    # metadata-preserving edits as BuildKit's local-context transfer.
    snapshot = directory / _context_hash(context, paths)
    if snapshot.is_dir():
        return snapshot
    included = set(paths)

    def omit(path, names):
        relative = Path(path).relative_to(context)
        return [name for name in names if relative / name not in included]

    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=directory, prefix=".snapshot-") as tmp:
        copied = Path(tmp) / "context"
        shutil.copytree(context, copied, symlinks=True, copy_function=shutil.copy2, ignore=omit)
        # Hash the copy too, so an edit during copying cannot publish different
        # contents under the earlier hash. Docker only reads the finished copy.
        snapshot = directory / _context_hash(copied, paths)
        try:
            os.rename(copied, snapshot)
        except OSError as e:
            if e.errno not in (errno.EEXIST, errno.ENOTEMPTY) or not snapshot.is_dir():
                raise
            # Another process published this complete snapshot first.
    return snapshot


_CARGO_DOCKERFILE = """\
# syntax=docker/dockerfile:1
# Generated by inspect_fictionet: the cargo example {name}, static, on scratch.
FROM {rust_image} AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \\
    --mount=type=cache,target=/src/target,id=inspect-fictionet-{key} \\
    find . -name '*.rs' -exec touch {{}} + \\
    && cargo build --release {cargo_args} --example {name} \\
    && cp target/release/examples/{name} /world

FROM scratch
COPY --from=build /world /world
USER 65532:65532
ENTRYPOINT ["/world"]
"""

_CARGO_DOCKERIGNORE = "target\n**/target\n**/downloads\n.git\n.venv\n**/.venv\nnode_modules\n"


def _cargo_build(example: CargoExample, cache: Path) -> Build:
    crate = Path(example.crate).resolve()
    if not (crate / "Cargo.toml").is_file():
        raise FileNotFoundError(f"world: no Cargo.toml in {crate}")
    cargo_args = []
    if example.package:
        cargo_args += ["-p", example.package]
    if example.features:
        cargo_args += ["--features", ",".join(example.features)]
    key = _short_key(f"{crate}|{example.name}|{example.package}")
    text = _CARGO_DOCKERFILE.format(
        name=example.name, rust_image=example.rust_image, key=key, cargo_args=" ".join(cargo_args)
    )
    dockerfile = _write_once(cache / "build", "world.Dockerfile", text)
    # BuildKit reads <Dockerfile>.dockerignore next to the Dockerfile.
    ignore = dockerfile.parent / "world.Dockerfile.dockerignore"
    if not ignore.is_file() or ignore.read_text() != _CARGO_DOCKERIGNORE:
        _write_atomic(ignore, _CARGO_DOCKERIGNORE)
    return Build(dockerfile=dockerfile, context=crate)
