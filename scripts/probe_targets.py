"""Shared validation for Forti connectivity probe targets."""
import json
import re
from pathlib import Path

_HOST_RE = re.compile(r"[A-Za-z0-9.-]+\Z")
_INTERFACE_RE = re.compile(r"(?:utun|any|[A-Za-z][A-Za-z0-9._-]*)\Z")
_FIELDS = {"host", "port", "expected_interface"}


def validate_target(target):
    if not isinstance(target, dict) or set(target) != _FIELDS:
        raise ValueError("target must contain only host, port, expected_interface")
    host = target["host"]
    port = target["port"]
    interface = target["expected_interface"]
    if not isinstance(host, str) or not host or not _HOST_RE.fullmatch(host):
        raise ValueError("target has an invalid host")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError(f"target {host!r} has an invalid port")
    if not isinstance(interface, str) or not _INTERFACE_RE.fullmatch(interface):
        raise ValueError(f"target {host!r} has an invalid expected_interface")
    return {"host": host, "port": port, "expected_interface": interface}


def validate_targets(document):
    if (not isinstance(document, dict)
            or set(document) != {"targets"}
            or not isinstance(document["targets"], list)
            or not document["targets"]):
        raise ValueError("probe-targets.json must contain only a nonempty 'targets' array")
    targets = []
    seen = set()
    for index, value in enumerate(document["targets"]):
        try:
            target = validate_target(value)
        except ValueError as error:
            raise ValueError(f"probe target {index}: {error}") from error
        key = tuple(target.values())
        if key in seen:
            raise ValueError(f"probe target {index} is duplicated")
        seen.add(key)
        targets.append(target)
    return targets


def load_targets_file(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("probe-targets.json must not be a symlink")
    try:
        with path.open() as stream:
            document = json.load(stream)
    except OSError as error:
        raise ValueError(str(error)) from error
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON: {error}") from error
    validate_targets(document)
    return document
