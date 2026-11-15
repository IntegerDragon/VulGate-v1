# Native plthook backend

Frida-Python 注入的**原生热补丁后端**：不 patch 机器码、不需要 trampoline，改 GOT/PLT 表项。
适合动态链接、经 PLT 调用导出符号的目标；PASS 直接 `dlsym(RTLD_DEFAULT, symbol)` 调原函数。

## 组件

- `runtime/native/build.py`：从 VulGate manifest/action catalog **生成并编译**原生 agent `.so`
- `runtime/native/run.py`：Frida Python 注入器（读并校验 bundle、probe/install/uninstall、回执）
- `tests/test_native_bundle.py`：生成器单测 + 真实多进程 BLOCK/PASS 验证（各 6 个进程）

## 支持范围

- guards：`symbol`（不支持 offset）、标量 `arg_types`、标量 `return_type`、`rule` 字节码、`step_limit`、`action_id`
- 动作：`return_int/int64/void/null/float/double`、`writes`（u32/u64/pointer 常量值）、`errno`
- 语义：PASS / BLOCK；`probe`、`install`、`uninstall`、`installed`、每 guard blocked/passed 计数
- bundle：沿用 `runtime.frida.run.load_bundle`（schema、digest、`VULGATE_BUNDLE_KEY` 签名校验、rule 加载）
- 错误码：10 无 guard、11 符号缺失、12 规则非法、13 动作不支持、14 plthook 不可用、20 安装失败、21 卸载失败
- 不支持（明确拒绝）：offset 挂点、observers/maps、shim、varargs、VM selectors、`calls`/`return_string` 动作、静态/内部直接调用

## 使用

```sh
# 依赖 plthook（默认 /tmp/mature-hooks/plthook，可用 --plthook-dir 指定）
python -m runtime.native.build --manifest m.json --catalog a.json --output build/native/agent.so
python -m runtime.native.run --spawn ./target --manifest m.json --catalog a.json \
    --duration 5 --build-dir build/native
python -m runtime.native.run --pid 1234 --manifest m.json --catalog a.json --check-only
```

`--check-only` 只 probe；否则 install 后等待 `--duration`（可省略 → 直到 Ctrl+C），再卸载并输出
`bundle_digest/backend/probe_code/install_code/uninstall_code/status` 回执。

## 验证结果（WSL Ubuntu-24.04）

- `tests/test_native_bundle.py`：**7 passed**
  - 生成器：拒绝 offset/observations、渲染 guard/动作、plthook 缺失时报错
  - 单次 live：BLOCK 调用返回 -73、计数 >0、卸载后 105、退出 0；PASS 调用原函数、passed 计数 >0、退出 0
  - 多进程：BLOCK/PASS 各 **5 个独立进程**，全部安装/运行/卸载/退出干净

## 已知限制 / 后续

- 仅覆盖 PLT 调用；同文件内部直接调用、静态链接、stripped 目标需要 inline 后端（funchook BLOCK 已验证 20/20；
  PASS 在 funchook trampoline 下仍不稳定，需自建 trampoline 或换 hook 引擎）。
- 尚未接 smoke 自证、observers/maps、metrics 事件流/熔断；当前只暴露每 guard 计数器与回执。
- `run.py` 作为注入器保持 Frida 会话到目标退出；`--spawn` 结束时 kill 目标（daemon 场景由上层管理）。
- 未覆盖 ARM64/Windows/macOS。
