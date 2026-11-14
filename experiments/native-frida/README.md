# 最小验证：Frida 热挂载 + 原生 CModule 门控 + 自有内联补丁

目标：在“热补丁、尽量不重建目标、可移植、安装/运行开销低”的约束下，验证
**Frida 负责注入，门控逻辑用原生 C（CModule）执行，不经过 JS 回调**这条路线。

## 结论

**可行**。已验证：

1. Frida `CModule` 编译出的原生函数作为 `Interceptor.replace` 替换体，在 4 个 pthread 上稳定执行；
2. 把 `runtime/vm.c` 嵌入 CModule（栈上状态）后，BLOCK 在 4 线程 × 50k 次调用中 100% 生效；
3. 自建 x86-64 trampoline + 14 字节绝对跳转 inline patch 后，PASS 能调用真正原函数（原函数体正常执行），BLOCK 跳过原函数；
4. 卸载时恢复原始字节，行为回到未打补丁状态。

## 实测（`probe.py` 输出）

| 动作 | 单次调用 | 4 线程 × 50k | 安装耗时 | 单次开销 |
|---|---|---|---|---|
| 未打补丁 | 返回 105 | `total=200000, blocked=0` | — | 约 65–85 ns/call |
| PASS | 返回 105（原函数体执行） | `total=200000, blocked=0` | 7.7 ms | 约 223 ns/call（+~140–160 ns） |
| BLOCK | 返回 -73（原函数体未执行） | `total=200000, blocked=200000` | 9.2 ms | 约 178 ns/call（+~90 ns） |

> 计时包含 fixture 线程循环和 JSON 输出开销，只用于判断量级；未做严格基准。
> fixture 的 `body_calls` 是非原子计数，多线程下会丢增量，因此不用于 PASS 的精确断言。

## 实现要点

- **CModule 状态必须放栈上**：Frida CModule 的数据段是只读的，`static` 可写变量会在首次写入时触发
  `access violation`。做法是每次调用在栈上构造 `shadow_program`（指向只读 `code[]`），不写静态数据。
- **PASS 需要自己的 trampoline**：CModule 无法取得 Frida 内部的原函数 trampoline，因此先在替换前
  复制目标函数前若干完整指令到可执行内存，再追加“绝对跳回 target+size”的跳板；CModule 通过编译期常量
  调用该跳板。当前只支持前 14 字节内没有 RIP-relative 操作数、跳转/调用的 prologue。
- **补丁本身用自己的 inline patch**：不用 `Interceptor.replace`，而是用 `Memory.patchCode` 写入
  14 字节 `movabs rax, guard; jmp rax`，因此 trampoline 的跳回位置可控；卸载时恢复原始字节。
- **CModule 里的 VM**：把 `runtime/autoshield.h` + `runtime/vm.c` 去掉系统 include、去掉文件加载函数、
  用自带 memset/memcpy 和 `safe_read` 占位，塞进 CModule 源码；BLOCK/PASS 由 VM 判定。

## 已验证的边界

- 运行在 Linux x86-64、动态链接 fixture；Frida 17.26.2；
- 4 线程并发命中，无崩溃；
- 安装约 8–9 ms（CModule 编译 + 补丁），运行期开销约 +0.1 µs/call 量级。

## 尚未验证 / 生产化缺口

- **prologue 重定位**：RIP-relative 操作数、相对跳转/调用、短 prologue（<14 字节）需要完整指令重定位器
  （可用 Frida `Instruction` 的 operand 信息实现，或换 funchook 等成熟引擎）；
- **运行中打补丁的线程安全**：当前在目标线程启动前 patch；生产需要在 patch 时暂停所有线程（Frida
  `Thread.suspend`/`Process.enumerateThreads`），并处理正在执行原函数的线程；
- **W^X / 加固环境**：`Memory.protect` 可执行内存、macOS hardened runtime、Windows CFG/EDR 未验证；
- **ARM64**：跳板与 CModule 代码需按 AArch64 重写；
- **CModule/TinyCC 限制**：无系统头文件、数据段只读、编译耗时随源码增大；
- 未接入现有 manifest/action/observer/map/smoke/metrics 生命周期，只是可行性探针。

## 运行

```sh
# 先生成 fixture
python -m runtime.frida.build --output build/frida-linux --with-fixture
# WSL 中运行探针
PYTHONPATH=/tmp/vulgate-frida-deps-20261111 python3 experiments/native-frida/probe.py
```
