"""Bind requested actions to replayed source candidates, without deployment authority.

The catalog is supplied separately from the DSL. Its claims are not trusted:
source hashes and candidate discovery are recomputed before IDs are resolved.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from tools.frontier import analyze_sources
from tools.frontier.ctypes import MODELS


ACTION_NAMES = ("unsafe_action", "unknown_action", "error_action")


def bind_actions(metadata, catalog=None):
    binding = {"status": "unbound", "authorized": False, "actions": {},
               "deployment_blockers": ["target build/ABI not verified", "full action/ownership/type contracts not verified",
                                       "predicate/coverage contracts not verified"]}
    errors = []
    selected = {name: metadata.get(name, {}).get("candidate_id") for name in ACTION_NAMES}
    if catalog is None:
        if any(selected.values()):
            errors.append("candidate IDs require a separately supplied frontier report")
        return binding, errors
    if not isinstance(catalog, dict) or catalog.get("schema_version") != 2:
        return binding, ["unsupported frontier report schema"]
    inputs = catalog.get("input_files")
    if not isinstance(inputs, list) or not inputs:
        return binding, ["frontier report has no pinned input files"]
    paths, hashes = [], {}
    try:
        for item in inputs:
            path = Path(item["file"])
            if not path.is_absolute():
                return binding, ["frontier binding requires absolute source paths"]
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != item["sha256"]:
                return binding, [f"frontier source changed: {path}"]
            if str(path) in hashes:
                return binding, [f"duplicate frontier input: {path}"]
            paths.append(path)
            hashes[str(path)] = digest
        target = catalog.get("requested_function") or catalog.get("dangerous_function")
        if not isinstance(target, str) or not target:
            return binding, ["frontier report has no analyzed target"]
        analysis = catalog.get("analysis", {})
        model = analysis.get("integer_model", "portable") if isinstance(analysis, dict) else None
        if not isinstance(model, str) or model not in MODELS:
            return binding, ["frontier report has an unsupported integer model"]
        current = analyze_sources(paths, target, str(catalog.get("id", "")), integer_model=model)
        if any(hashlib.sha256(p.read_bytes()).hexdigest() != hashes[str(p)] for p in paths):
            return binding, ["frontier source changed during replay"]
    except (KeyError, TypeError, ValueError, OSError) as exc:
        return binding, [f"cannot replay frontier inputs: {exc}"]

    candidates = {item["candidate_id"]: item for item in current["candidates"]}
    binding["source_hashes"] = hashes
    binding["catalog_replayed"] = True
    binding["integer_model"] = model
    binding["integer_model_verified_against_build"] = False
    for name, ident in selected.items():
        requested = metadata.get(name, {})
        if not ident:
            binding["actions"][name] = {"status": "unbound", "authorized": False}
            continue
        candidate = candidates.get(ident) if isinstance(ident, str) else None
        if candidate is None:
            errors.append(f"{name}: candidate ID is absent from replayed analysis")
            continue
        if metadata.get("target_function") != candidate["function"]:
            errors.append(f"{name}: target function does not match the selected candidate")
            continue
        if metadata.get("protection_boundary") != "function_entry" or candidate["position"] != "entry":
            errors.append(f"{name}: only the selected function entry is bound")
            continue
        expression = candidate["return_value"]
        if "return_expression" in requested and requested["return_expression"] != expression:
            errors.append(f"{name}: return expression differs from the selected candidate")
            continue
        semantics = candidate["return_semantics"]
        value = semantics["converted_integer"] if semantics["conversion_issue"] is None else None
        entry = {"status": "source_matched", "authorized": False, "candidate_id": ident,
                 "function": candidate["function"], "position": "entry", "return_expression": expression,
                 "return_kind": candidate["return_kind"], "resolved_integer": value,
                 "return_semantics": semantics,
                 "caller_contract": candidate["caller_contract"],
                 "uncovered_runtime_callers": candidate["uncovered_runtime_callers"],
                 "coverage_condition": candidate["coverage_condition"], "pending": []}
        if "value" not in requested:
            entry["pending"].append("runtime action value not supplied")
        elif type(requested["value"]) is not int:
            errors.append(f"{name}: runtime action value must be an integer")
        elif value is None:
            entry["pending"].append("return expression has no verified integer/ABI encoding")
        elif requested["value"] != value:
            errors.append(f"{name}: runtime return value differs from the selected candidate")
        if requested.get("error"):
            entry["pending"].append("additional error-state mutation has no bound effect contract")
        if candidate["caller_contract"] != "confirmed_in_model":
            entry["pending"].append("caller contract is incomplete")
        if candidate["uncovered_runtime_callers"]:
            entry["pending"].append("runtime call coverage is incomplete")
        if candidate["relation"] == "creation":
            entry["pending"].append("creation/activation assumptions require validation")
        binding["actions"][name] = entry
    if errors:
        binding["status"] = "mismatch"
    elif all(binding["actions"].get(name, {}).get("status") == "source_matched" for name in ACTION_NAMES):
        binding["status"] = "source_matched"
    else:
        binding["status"] = "incomplete"
    return binding, errors
