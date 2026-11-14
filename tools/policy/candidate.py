"""Candidate parsing for VulGate policies.

The first v0.2 compiler intentionally avoids a full YAML dependency.  It accepts
the prompt schema's simple key/value structure plus a fenced DSL block.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class PolicyCandidate:
    metadata: dict[str, Any]
    dsl: str

    def to_markdown(self) -> str:
        return "---\n" + _dump_yaml(self.metadata) + "---\n\n```python\n" + self.dsl.strip() + "\n```\n"


def parse_candidate_file(path: Path) -> PolicyCandidate:
    return parse_candidate_text(path.read_text(encoding="utf-8"))


def parse_candidate_text(text: str) -> PolicyCandidate:
    stripped = text.strip()
    if stripped.startswith("{"):
        payload = json.loads(stripped)
        return PolicyCandidate(metadata=payload["metadata"], dsl=payload["dsl"])

    yaml_text = _extract_fence(text, "yaml") or _text_before_python_fence(text)
    dsl_text = _extract_fence(text, "python") or _extract_indented_dsl(yaml_text) or text
    metadata = _parse_simple_yaml(yaml_text)
    metadata.pop("dsl", None)
    return PolicyCandidate(metadata=metadata, dsl=dsl_text.strip() + "\n")


def _extract_fence(text: str, lang: str) -> str | None:
    match = re.search(r"```" + re.escape(lang) + r"\s*\n(.*?)\n```", text, re.S)
    if not match:
        return None
    return match.group(1).strip("\n")


def _text_before_python_fence(text: str) -> str:
    match = re.search(r"```python\s*\n", text)
    if not match:
        return text.strip()
    return text[: match.start()].strip()


def _extract_indented_dsl(yaml_text: str) -> str | None:
    match = re.search(r"^dsl:\s*\|\s*\n((?:[ \t]+.*\n?)+)", yaml_text, re.M)
    if not match:
        return None
    lines = match.group(1).splitlines()
    return "\n".join(line[4:] if line.startswith("    ") else line.lstrip() for line in lines).strip() + "\n"


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            index += 1
            continue
        if not line.startswith(" ") and ":" in line:
            key, raw_value = line.split(":", 1)
            value = raw_value.strip()
            if value == "":
                index += 1
                if key.strip() in {"source_dependencies", "uncertainties"}:
                    items, index = _parse_list(lines, index)
                    result[key.strip()] = items
                else:
                    nested, index = _parse_nested(lines, index)
                    result[key.strip()] = nested
            else:
                result[key.strip()] = _parse_scalar(value)
                index += 1
        else:
            index += 1
    return result


def _parse_nested(lines: list[str], index: int) -> tuple[dict[str, Any], int]:
    nested: dict[str, Any] = {}
    while index < len(lines):
        line = lines[index]
        if not line.startswith(" ") and ":" in line:
            break
        if not line.strip() or line.lstrip().startswith("#"):
            index += 1
            continue
        stripped = line.strip()
        if ":" not in stripped:
            index += 1
            continue
        key, value = stripped.split(":", 1)
        nested[key.strip()] = _parse_scalar(value.strip())
        index += 1
    return nested, index


def _parse_list(lines: list[str], index: int) -> tuple[list[Any], int]:
    items: list[Any] = []
    while index < len(lines):
        line = lines[index]
        if not line.startswith(" ") and ":" in line:
            break
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        if stripped.startswith("- "):
            item_text = stripped[2:].strip()
            if ":" in item_text:
                key, value = item_text.split(":", 1)
                items.append({key.strip(): _parse_scalar(value.strip())})
            else:
                items.append(_parse_scalar(item_text))
        elif ":" in stripped and items and isinstance(items[-1], dict):
            key, value = stripped.split(":", 1)
            items[-1][key.strip()] = _parse_scalar(value.strip())
        index += 1
    return items, index


def _parse_scalar(value: str) -> Any:
    if value in {"true", "false"}:
        return value == "true"
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    try:
        return int(value, 0)
    except ValueError:
        return value


def _dump_yaml(value: Any, indent: int = 0) -> str:
    prefix = " " * indent
    if isinstance(value, dict):
        blocks: list[str] = []
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                blocks.append(f"{prefix}{key}:\n" + _dump_yaml(item, indent + 2))
            else:
                blocks.append(f"{prefix}{key}: {_dump_scalar(item)}")
        return "\n".join(blocks) + "\n"
    if isinstance(value, list):
        lines: list[str] = []
        for item in value:
            if isinstance(item, dict):
                first = True
                for key, subitem in item.items():
                    prefix_item = f"{prefix}- " if first else f"{prefix}  "
                    lines.append(prefix_item + f"{key}: {_dump_scalar(subitem)}")
                    first = False
            else:
                lines.append(f"{prefix}- {_dump_scalar(item)}")
        return "\n".join(lines) + ("\n" if lines else "")
    return f"{prefix}{_dump_scalar(value)}\n"


def _dump_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if value is None:
        return ""
    return json.dumps(str(value))
