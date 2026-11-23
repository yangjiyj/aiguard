#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import re
import shlex
import sys
from typing import Iterator


ARG_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
STAGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
VARIABLE_RE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")


class DockerfileParseError(ValueError):
    pass


def logical_instructions(text: str, source: str) -> Iterator[tuple[int, str]]:
    escape = "\\"
    pending: list[str] = []
    pending_line = 0
    instructions_started = False

    for line_number, raw_line in enumerate(text.splitlines(), 1):
        stripped = raw_line.lstrip()
        if not pending and stripped.startswith("#"):
            if not instructions_started:
                match = re.fullmatch(r"#\s*escape\s*=\s*([\\`])\s*", stripped, re.IGNORECASE)
                if match:
                    escape = match.group(1)
            continue
        if not pending and not stripped:
            continue

        instructions_started = True
        trimmed = raw_line.rstrip()
        trailing = len(trimmed) - len(trimmed.rstrip(escape))
        continued = trailing % 2 == 1
        if not pending:
            pending_line = line_number
        pending.append((trimmed[:-1] if continued else trimmed).strip())
        if continued:
            continue

        instruction = " ".join(part for part in pending if part)
        pending.clear()
        if instruction:
            yield pending_line, instruction

    if pending:
        raise DockerfileParseError(
            f"{source}:{pending_line}: unterminated Dockerfile continuation"
        )


def expand_reference(reference: str, arguments: dict[str, str | None], source: str, line: int) -> str:
    resolved = reference
    for _ in range(len(arguments) + 2):
        unresolved: set[str] = set()

        def replace(match: re.Match[str]) -> str:
            name = match.group(1) or match.group(2)
            value = arguments.get(name)
            if value is None:
                unresolved.add(name)
                return match.group(0)
            return value

        updated = VARIABLE_RE.sub(replace, resolved)
        if unresolved:
            names = ",".join(sorted(unresolved))
            raise DockerfileParseError(
                f"{source}:{line}: unresolved build argument in FROM: {names}"
            )
        if updated == resolved:
            return updated
        resolved = updated
    raise DockerfileParseError(f"{source}:{line}: recursive build argument in FROM")


def parse_dockerfile(text: str, source: str = "<Dockerfile>") -> list[dict[str, object]]:
    global_arguments: dict[str, str | None] = {}
    stages: set[str] = set()
    bases: list[dict[str, object]] = []
    from_index = 0
    seen_from = False

    for line_number, instruction in logical_instructions(text, source):
        fields = instruction.split(None, 1)
        keyword = fields[0].upper()
        body = fields[1].strip() if len(fields) == 2 else ""

        if keyword == "ARG" and not seen_from:
            if not body:
                raise DockerfileParseError(f"{source}:{line_number}: empty ARG instruction")
            name, separator, default = body.partition("=")
            name = name.strip()
            if not ARG_NAME_RE.fullmatch(name):
                raise DockerfileParseError(f"{source}:{line_number}: invalid ARG name: {name}")
            global_arguments[name] = default.strip() if separator else None
            continue
        if keyword != "FROM":
            continue

        seen_from = True
        try:
            tokens = shlex.split(body, posix=True)
        except ValueError as error:
            raise DockerfileParseError(f"{source}:{line_number}: invalid FROM: {error}") from error
        while tokens and tokens[0].startswith("--"):
            tokens.pop(0)
        if len(tokens) not in {1, 3} or (len(tokens) == 3 and tokens[1].upper() != "AS"):
            raise DockerfileParseError(f"{source}:{line_number}: invalid FROM instruction")

        raw_reference = tokens[0]
        stage = tokens[2] if len(tokens) == 3 else None
        reference = expand_reference(raw_reference, global_arguments, source, line_number)
        internal = reference.lower() in stages
        if not internal and reference.lower() != "scratch":
            name, separator, digest = reference.rpartition("@")
            if not separator or not name or not DIGEST_RE.fullmatch(digest):
                raise DockerfileParseError(
                    f"{source}:{line_number}: external FROM is not pinned to a sha256 digest: {reference}"
                )
            bases.append({
                "from_index": from_index,
                "stage": stage,
                "reference": reference,
                "digest": digest,
            })
        if stage is not None:
            if not STAGE_NAME_RE.fullmatch(stage):
                raise DockerfileParseError(f"{source}:{line_number}: invalid stage name: {stage}")
            stages.add(stage.lower())
        from_index += 1

    return bases


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dockerfile", required=True, help="Dockerfile path, or - for stdin")
    args = parser.parse_args()

    source = args.dockerfile
    try:
        if source == "-":
            text = sys.stdin.read()
            source = "<stdin>"
        else:
            text = pathlib.Path(source).read_text(encoding="utf-8")
        payload = parse_dockerfile(text, source)
    except (OSError, UnicodeError, DockerfileParseError) as error:
        print(f"[error] Dockerfile base image parsing failed: {error}", file=sys.stderr)
        return 1

    json.dump(payload, sys.stdout, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
