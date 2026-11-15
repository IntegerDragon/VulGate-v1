# Native backends (bundle-driven, Frida Python injector)

两个原生后端，网入现有 VulGate bundle/语义，注入器使用 Frida Python：

| 后端 | 机制 | 语义 | 覆盖 |
|---|---|---|---|
| `plthook`（默认） | GOT/PLT 表项替换 | BLOCK + **PASS**（`dlsym` 调原函数） | 动态符号的 PLT 调用 |
| `inline` | funchook 改写函数入口 + STW | **仅 always_block 的 BLOCK** | symbol / offset 挂点，含同文件内部调用 |

PASS 选择 plthook 的原因：funchook trampoline 在高频并发 PASS 调用下会偶发破坏状态；plthook 无代码改写，
单次 live PASS 20/20、5 进程回归全部通过。

## 组件

- `runtime/native/build.py`：manifest/action catalog → 生成并编译原生 agent `.so`
- `runtime/native/run.py`：Frida Python 注入器（bundle 校验、probe/install/uninstall、回执）
- `runtime/native/native_stw.c`：inline 后端的信号停车 STW
- `tests/test_native_bundle.py`：生成器单测 + 单进程/多进程 BLOCK、PASS、offset、launcher 注入测试

## 支持范围

- guards：`symbol` 或 `offset`（inline；offset 需 `module`）、标量 `arg_types/return_type`、`rule`、`step_limit`、`action_id`
- 动作：`return_int/int64/void/null/float/double`、`writes`（u32/u64/pointer 常量）、`errno`
- 语义：PASS/BLOCK（plthook）；BLOCK-only（inline，要求 `always_block: true`）
- probe/install/uninstall/installed/每 guard blocked/passed 计数、bundle digest、稳定错误码
- bundle：复用 `runtime.frida.run.load_bundle`（schema、digest、`VULGATE_BUNDLE_KEY` 验签、rule 加载）
- 错误码：10 无 guard、11 符号/地址缺失、12 规则非法、13 动作不支持、14 plthook 不可用、20 安装失败、
  21 卸载失败、22 STW 失败

不支持（明确拒绝）：observers/maps、shim、varargs、VM selectors、`calls`/`return_string`、inline PASS、
静态链接目标、非 PLT 的 plthook 覆盖。

## 使用

```sh
# plthook（PASS/BLOCK）
python -m runtime.native.run --spawn ./target --manifest m.json --catalog a.json \
    --duration 5 --backend plthook

# inline（BLOCK-only，symbol 或 offset）
python -m runtime.native.run --pid 1234 --manifest m.json --catalog a.json \
    --backend inline --funchook-dir /path/to/funchook --check-only
python -m runtime.native.run --spawn ./target --manifest m.json --catalog a.json \
    --backend inline --funchook-dir /path/to/funchook --duration 5
```

`--check-only` 只 probe；否则 install → 等待 `--duration`（省略则到 Ctrl+C）→ uninstall，输出回执
`backend/bundle_digest/probe_code/install_code/uninstall_code/status`。

## 验证（WSL Ubuntu-24.04）

- `tests/test_native_bundle.py`：**13 passed**
  - 生成器：plthook 拒绝 offset/observations；inline 要求 always_block、接受 symbol/offset；渲染 guard/动作
  - plthook：单次 BLOCK/PASS + 各 5 进程多进程回归
  - inline：symbol 与 offset 单次 BLOCK（4 线程热循环，STW），各 5 进程回归
  - launcher：`--spawn` inline 注入、install/uninstall 回执
- 实测行为：BLOCK 调用返回 action、blocked 计数增长、卸载后恢复 105；PASS 调用原函数、passed 计数增长、
  退出码 0。

## 已知限制 / 后续

- inline PASS 不可用（funchook trampoline 问题），PASS 场景请用 plthook；内联 && PASS 同时需要时，需要自建
  trampoline 或换 hook 引擎。
- 未接 observers/maps、smoke 自证、统一 metrics/熔断；当前提供每 guard 计数与回执。
- 未验证 ARM64/Windows/macOS；plthook 依赖外部 plthook 源码（`--plthook-dir`），inline 依赖 funchook
  （`--funchook-dir`）。
- patch 期间新建线程的竞态未处理（按需求忽略）。
