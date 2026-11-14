from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyze import analyze_sources
from .ctypes import MODELS


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(
        description="从 Linux 内核或用户态 C 源码里选出安全拦截点和已有失败返回值"
    )
    parser.add_argument("manifest", nargs="?", type=Path, help="包含 dangerous_function 和 sources 的 JSON")
    parser.add_argument("--func", help="危险函数名")
    parser.add_argument("--src", action="append", type=Path, default=[], help="C 源码，可重复。需要包含危险函数和它的调用方")
    parser.add_argument("--id", default="", help="漏洞编号，只用于输出")
    parser.add_argument("--json", action="store_true", help="只打印 JSON")
    parser.add_argument("--integer-model", choices=MODELS, help="整数分析假设，默认 portable；不代表已验证目标构建")
    args = parser.parse_args(argv)
    try:
        ident, func, sources, integer_model = _inputs(args)
    except (OSError, ValueError) as exc:
        parser.error(f"无法读取输入：{exc}")
    if not func or not sources:
        parser.error("需要 --func 和至少一个 --src，或者一份 manifest")
    missing = [str(path) for path in sources if not path.is_file()]
    if missing:
        print("找不到源码: " + ", ".join(missing), file=sys.stderr)
        return 1
    try:
        result = analyze_sources(sources, func, ident, integer_model=integer_model)
    except (OSError, UnicodeError) as exc:
        parser.error(f"无法读取源码：{exc}")
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        _print_human(result)
    if result["status"] in {"found", "partial"}:
        return 0
    if result["status"] == "insufficient_input":
        return 3
    return 2


def _inputs(args: argparse.Namespace) -> tuple[str, str, list[Path], str]:
    if args.manifest:
        payload = json.loads(args.manifest.read_text(encoding="utf-8-sig"))
        if not isinstance(payload, dict):
            raise ValueError("manifest 必须是 JSON 对象")
        names = payload.get("sources", [])
        if not isinstance(names, list) or any(not isinstance(name, str) or not name for name in names):
            raise ValueError("sources 必须是非空路径字符串组成的数组")
        if not isinstance(payload.get("dangerous_function", ""), str):
            raise ValueError("dangerous_function 必须是字符串")
        root = args.manifest.parent
        sources = [root / name for name in names]
        sources.extend(args.src)
        model = args.integer_model or payload.get("integer_model", "portable")
        if not isinstance(model, str) or model not in MODELS:
            raise ValueError("未知 integer_model")
        return str(payload.get("id", args.id)), str(payload.get("dangerous_function", args.func or "")), sources, model
    return args.id, args.func or "", list(args.src), args.integer_model or "portable"


def _print_human(result: dict) -> None:
    if result["status"] in {"found", "partial"}:
        print(f"拦截点：{result['intercept']} 入口")
        print(f"候选返回值：{result['return_value']}")
        print("分析模式：源码启发式，不能直接作为 ENFORCE 依据")
        print(f"整数分析假设：{result['analysis']['integer_model']}（未验证目标构建）")
        print(result["reason"])
        for item in result["candidates"]:
            if item["before_acquire"]:
                place = "函数在取得资源前就返回过这个值"
            else:
                place = "返回值来源在资源操作之后，入口契约仍需核验"
            source = item['return_location']
            print(f"候选：{item['function']} 入口 返回 {item['return_value']}（{item['relation']}，{place}；调用契约 {item['caller_contract']}；{source['file']}:{source['line']}）")
        for name in result["uncovered"]:
            print(f"未覆盖调用：{name}")
        return
    print(f"结果：{result['status']}")
    print(result["reason"])


if __name__ == "__main__":
    raise SystemExit(main())
