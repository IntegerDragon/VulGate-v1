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

