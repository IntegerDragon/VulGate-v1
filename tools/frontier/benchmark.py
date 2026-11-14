"""Replay a locally saved, manually reviewed source corpus. No network access."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .analyze import analyze_sources


def run_corpus(manifest: Path) -> dict:
    payload = json.loads(manifest.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict) or not isinstance(payload.get("cases"), list):
        raise ValueError("corpus 必须包含 cases 数组")
    rows = []
    ids = set()
    for case in payload["cases"]:
        if not isinstance(case, dict) or not isinstance(case.get("id"), str) or case["id"] in ids:
            raise ValueError("每个 case 需要唯一的字符串 id")
        ids.add(case["id"])
        if not isinstance(case.get("dangerous_function"), str) or not case["dangerous_function"]:
            raise ValueError(f"{case['id']}: 缺少 dangerous_function")
        if not isinstance(case.get("sources"), list) or not case["sources"]:
            raise ValueError(f"{case['id']}: 缺少 sources")
        expected = case.get("expected_candidates")
        if not isinstance(expected, list) or any(not isinstance(c, list) or len(c) != 3
                                                 or any(not isinstance(s, str) for s in c) for c in expected):
            raise ValueError(f"{case['id']}: expected_candidates 必须是 [函数, 返回值, 关系] 数组")
        files, errors = [], []
        for source in case["sources"]:
            if not isinstance(source, dict) or not isinstance(source.get("path"), str) or not isinstance(source.get("sha256"), str):
                raise ValueError(f"{case['id']}: 每个 source 需要 path 和 sha256")
            path = manifest.parent / source["path"]
            if not path.is_file():
                errors.append(f"缺少源码: {source['path']}")
            elif hashlib.sha256(path.read_bytes()).hexdigest() != source["sha256"]:
                errors.append(f"源码哈希不一致: {source['path']}")
            files.append(path)
        if errors:
            rows.append({"id": case["id"], "check": "input_error", "errors": errors})
            continue
        result = analyze_sources(files, case["dangerous_function"], case["id"])
        actual = {(c["function"], c["return_value"], c["relation"]) for c in result["candidates"]}
        expected_set = {tuple(c) for c in expected}
        added, missing = sorted(actual - expected_set), sorted(expected_set - actual)
        status_matches = result["status"] == case.get("expected_status", result["status"])
        rows.append({"id": case["id"], "check": "matched" if not added and not missing and status_matches else "changed",
                     "new_unreviewed_candidates": added, "missing_reviewed_candidates": missing,
                     "status_matches": status_matches, "result": result})
    return {"schema_version": 1, "corpus": str(manifest),
            "meaning": "与已人工复核的固定源码基线比较；不是漏洞修复准确率或内核运行验证",
            "total": len(rows), "matched": sum(row["check"] == "matched" for row in rows),
            "cases": rows}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path, help="保存逐例 JSON 结果")
    args = parser.parse_args(argv)
    try:
        report = run_corpus(args.manifest)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(f"Reviewed corpus: {report['matched']}/{report['total']} matched")
    for case in report["cases"]:
        if case["check"] != "matched":
            print(f"{case['id']}: {case['check']}")
    return 0 if report["matched"] == report["total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
