# Frida 替换回调的多线程限制（实测记录）

日期：2026-11-15。结论先行：**Frida 17.26.2 的 `Interceptor.replace` + `NativeCallback` 在非主线程上执行稍复杂的 JS 会崩溃**；因此“多线程目标上的门控”目前不能靠 JS 回调完成。本文件记录证据与后续方向。

## 复现

目标：`tests/workloads/userspace/frida/fixture.c` 的 `fixture_target`，由 pthread 工作线程反复调用。

| 场景 | 结果 |
|---|---|
| 替换回调只 `return 7` | 正常（2/4 线程各 20 次） |
| 替换回调里 `Memory.alloc` / `send` / `Process.getCurrentThreadId()` / 读 JS 对象属性 | **进程 SIGSEGV（-11）** |
| `Interceptor.attach` 回调里做同样的 `Memory.alloc` / `send` | 正常 |
| 原生 shim（`Interceptor.replace(target, NativePointer)`）只返回常量 | 正常 |
| 原生 shim 内部经函数指针调用桥接库（`vg_run` / 空句柄） | 主线程正常，pthread 调用**挂起/崩溃** |
| 原生 shim 内不调用桥接库 | pthread 正常 |
| `NativeCallback(..., {scheduling: 'cooperative'})` | 不支持：`Error: expected a string`（第 4 参数只接受 ABI 字符串） |
| `attach` 的 `onEnter` 写 `rax/rsi` | 生效（参数/返回值寄存器可改） |
| 同回调改写 `rip/rsp` 试图提前返回 | **不生效**，原函数仍执行 |

## 结论

1. 不是我们的 fixture 或锁的问题：attach 路径在同样线程上完全正常。
2. 不是桥接库线程安全问题：空句柄调用也挂起，说明是“原生 shim → 桥接模块”的调用路径问题。
3. Frida 的 attach 无法跳过原函数（PC 改写被忽略），replace 的 JS 回调又不支持多线程 → **JS 门控在 pthread 上不可用**。

## 已实现的缓解

- `runtime/frida/lifecycle.py`：卸载时轮询 `callbacks active`，在回调静默后再撤销（避免带活跃回调卸载）。
- 观察点（`Interceptor.attach`）在多线程下可用：线程作用域的观测记录已通过测试（每个线程独立 scope）。
- 观测/决策计数、事件发送仍在主线程路径正常工作。

## 后续方向（多线程目标）

1. **原生替换型 shim + 原生桥接**：把 VM 调用链接进 shim 自身（静态编译 `runtime/vm.c`），彻底避开“shim → 独立桥接模块”的跨模块调用；若该路径在 pthread 可用，则可恢复多线程门控。
2. **LD_PRELOAD 部署模式**：对动态链接目标，用符号插入的原生库实现门控（无 Frida 回调），天然线程安全；与现有 `PatchSpec`/动作目录共用，但安装方式从 attach 改为启动时 preload。
3. **eBPF uprobe 模式**：内核侧挂载、用户态无需回调，适合生产多线程目标，但需要 root/eBPF 权限并重新实现动作执行。

在这三项完成前，多线程目标应明确标注“不支持多线程门控”，不得声称 WP6 完成。

## 2026-11-15 追加实验（方向 1 的结论）

- 原生 shim 通过函数指针调用桥接库的**平凡函数**（`vg_abi_version`）在 pthread 上正常；说明“shim → 桥接模块”的调用本身可用。
- 原生 shim 调用桥接库的 `vg_run`（即使传入空句柄、原地返回错误）在 pthread 上**挂起**；主线程正常。
- 把 `runtime/vm.c` **静态链接进 shim**（不经过桥接模块）后：主线程正常返回 BLOCK，pthread 上在写入进入/开始运行的标记后**不再返回**（`strace` 级标记为 IRDIRIRIR，缺少运行结束标记）。
- 因此阻塞点不是跨模块调用，而是“在 Frida 替换回调的 pthread 上执行 VM 路径”；`vm.c` 本身是纯 C 且无 TLS，仍无法解释该挂起（疑似 Gum 回调线程状态与较长用户态执行交互）。
- 结论：方向 1 不可行；多线程门控改为走 **方向 2（LD_PRELOAD）** 或方向 3（eBPF），并在完成前维持“多线程不支持”的标注。

## 2026-11-15 方向 2 落地：LD_PRELOAD 原生门控

新增 `runtime/preload/build.py`：按 manifest/actions 生成原生 `.so`，用符号插入定义被补丁函数，库内**静态链接 `runtime/vm.c`** 执行规则；BLOCK 执行动作，PASS 通过 `dlsym(RTLD_NEXT, ...)` 调真正实现。运行方式：

```sh
python -m runtime.preload.build --manifest m.json --catalog a.json --output libvgpreload.so
LD_PRELOAD=$PWD/libvgpreload.so ./target
```

实测（`tests/test_preload.py`，4 线程 × 25 次）：

| 场景 | 结果 |
|---|---|
| 无 preload | `total=100, blocked=0, calls=101`（含输出函数一次） |
| BLOCK preload | `total=100, blocked=100, calls=0, out=0, output_result=-1`（含多字段写动作） |
| PASS preload | `total=100, blocked=0, calls=101`（经 `dlsym(RTLD_NEXT)` 调用原函数） |

观察 map（thread-scoped）与递归也已验证：

- 观察 wrapper 与 guard wrapper 共用原生 map，scope 取 `pthread_self()`；4 线程各自把值写入同一 key，只有值 > 2 的 2 个线程被 BLOCK（`checked_ok=50, checked_blocked=50`），说明线程作用域隔离生效；
- `preload_recurse(4)` 在 PASS wrapper 下经“wrapper→real→递归 PLT→wrapper”返回 4，无崩溃。

限制：只覆盖**经过动态符号表（PLT）**的调用；观察 map 目前仅支持简单 `key_arg`/`value_arg`（无 selector/组合 key）；静态链接目标不适用。Frida attach 路径仍然不支持多线程门控。

## 2026-11-15 追加：Frida + 原生 CModule 路线可行（最小验证）

`experiments/native-frida/probe.py` 验证了“Frida 注入 + 原生 CModule 执行门控 + 自有 inline patch/trampoline”：

- CModule 原生函数在 4 个 pthread 上稳定执行；把 `runtime/vm.c` 嵌入 CModule（状态放栈上，CModule 数据段只读）后，BLOCK 4×50k 全部生效；
- PASS 经自建 trampoline 调用真正原函数（原函数体执行），BLOCK 跳过；卸载恢复原始字节；
- 实测安装约 8–9ms，运行期约 +0.1µs/call 量级（粗略计时，见 README）。

缺口：prologue 重定位、patch 时暂停线程、W^X/加固环境、ARM64、与现有 manifest/生命周期集成。完整说明见 `experiments/native-frida/README.md`。



