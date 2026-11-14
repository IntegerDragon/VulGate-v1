# 用户态补丁安装：完整工作清单（v2）

日期：2026-11-14。本文在早先同文件版本的基础上，按“源码/构建与运行版本一致、补丁天然可挂载、只做可行性检查”的新前提重写。

## 0. 前提与明确不做的事

前提（本次假设）：

1. **源码、编译选项与线上运行版本一致**：不处理版本漂移、不重建目标、不做发行版适配。
2. **补丁在编写时就是可挂载的**：不做自动切点上移、不做内联适配、不做 LTO/ICF 自动纠正。
3. **挂点可行性检查只回答“能不能挂”**：不能挂就返回错误码/错误信息并停止安装。
4. 不包含符号执行、补丁正确性验证、误伤统计。
5. 首要目标是 Linux x86-64 的 C/C++ 用户态应用；其他架构/语言只定义边界，不在本轮实现。

明确不做：

- 版本漂移检测与自动适配；
- 内联函数自动外移、切点自动上移；
- 任意语言/运行时（JIT）适配；
- 补丁语义正确性证明。

## 1. 目标定义

输入：

- `bundle`：`manifest.json`（guards/observers/maps/artifact 校验）+ `actions.json`（动作目录）+ `guard-*.bin`（VM 字节码）+ `bridge` 本地库；
- 目标：进程（pid/表达式/名称）或可执行文件（托管启动）。

输出（每个进程一份）：

```json
{
  "pid": 1234,
  "status": "installed_verified | installed_unverified | failed",
  "code": "E_OK | E_*",
  "message": "human readable",
  "bindings": [{"id": "...", "module": "...", "address": "0x..."}],
  "effect": {"triggered": true, "decision": "BLOCK", "value": "-73"},
  "decisions": 0,
  "blocks": 0
}
```

成功标准：**装上（可解释）→ 生效（有触发证据）→ 可安全卸载**；失败必须给出稳定错误码与可读原因，且不残留半装状态。

## 2. 错误码与结果模型（P0，所有后续工作的地基）

### 2.1 CLI 退出码

| 退出码 | 含义 |
|---|---|
| 0 | 全部目标安装成功（且若声明 smoke，全部触发成功） |
| 2 | 参数/用法错误 |
| 3 | bundle 本身无效（schema/字节码/动作目录不一致） |
| 4 | 挂点不可挂（解析失败、ABI 不支持等） |
| 5 | 权限/注入失败 |
| 6 | 目标不匹配（build-id/哈希/架构不符） |
| 7 | 部分目标失败（`--fail-fast` 下不会出现） |
| 8 | 已安装/重复安装 |
| 9 | smoke 未产生预期 BLOCK（已卸载，除非 `--smoke-warn-only`） |

### 2.2 挂点错误码

| 错误码 | 触发条件 |
|---|---|
| `E_ARCH_UNSUPPORTED` | 目标架构不是 x64（本轮） |
| `E_SCHEMA_INVALID` | bundle/动作目录 schema 不支持 |
| `E_MODULE_MISSING` | `manifest.module` 在目标进程中找不到 |
| `E_SYMBOL_MISSING` | 导出符号不存在、被 strip |
| `E_OFFSET_INVALID` | 偏移越界/不可执行 |
| `E_HOOK_NOT_ALIGNED` | 挂点地址不满足替换前提（可选检查） |
| `E_DUPLICATE_HOOK` | 两个 hook 指向同一地址 |
| `E_HOOK_INVALID` | hook 缺 id、id 重复、结构非法 |
| `E_MAP_INVALID` | map 定义非法（容量越界等） |
| `E_ARITY_UNSUPPORTED` | 参数个数 >6 或类型不在支持集合 |
| `E_RETURN_UNSUPPORTED` | 返回类型不在 `int/int64/pointer/void`（本轮）或与动作不符 |
| `E_ACTION_MISSING` | `action_id` 不在动作目录 |
| `E_ACTION_ABI_MISMATCH` | 动作类型与返回类型/参数类型不匹配 |
| `E_ACTION_WRITE_INVALID` | 动作写字段的目标参数不是 pointer 或偏移/宽度非法 |
| `E_ACTION_CALL_INVALID` | 动作附带调用（`calls`）的 module/symbol/参数/once 非法或不可解析 |
| `E_RULE_INVALID` | 字节码为空、长度非 8 倍数、超上限、VM 校验拒绝 |
| `E_MAP_MISSING` | guard/observer 引用了不存在的 map |
| `E_OBSERVER_INVALID` | 观测点操作/键/值声明非法 |
| `E_BRIDGE_ABI` | bridge 版本不匹配（`vg_abi_version`） |
| `E_ALREADY_INSTALLED` | 同一进程已安装同 bundle |
| `E_TARGET_BUSY` | 卸载/安装时仍有回调在跑 |
| `E_INJECT_DENIED` | ptrace 权限、Yama、LSM 拒绝 |
| `E_TARGET_EXITED` | 解析/安装期间目标退出 |
| `E_TARGET_MISMATCH` | 目标哈希/build-id 与 bundle 声明不符 |
| `E_SMOKE_FAILED` | 安装成功但触发项没有产生预期 BLOCK |

### 2.3 失败语义

- **进程内原子**：先把所有 guards/observers 解析并校验完，再统一 `Interceptor.replace`；任一项失败则整进程失败、不挂任何 hook（agent 现有 `install` 已按此实现，需扩展到 probe 与错误码）。
- **跨进程策略**：`--fail-fast`（默认：任一进程失败即停止并卸载已装）与 `--best-effort`（继续，汇总部分失败）。
- **失败即停**：挂点不可挂时不得“跳过该 hook 继续装其他 hook”。
- **不变量**：任何错误路径都不留下半个 hook、不残留 map、不改变目标行为。

## 3. 工作包

### WP1 挂点可行性检查与错误码（P0）

- 新增 agent RPC `probe(config, catalog)`：不挂载，只做解析与校验，返回 `{ok, bindings, errors[{code,message,hook}]}`；不加载 bridge，`E_BRIDGE_ABI` 由安装阶段返回；
- 校验项：架构、schema、模块/符号/偏移、地址可执行、参数/返回 ABI、动作目录与写字段、规则字节码（长度/范围/步数上限）、map/observer、hook id 与重复地址、已安装状态；
- CLI：`run.py --check-only`、`multiproc.py --check`（只探测不安装）、`--fail-fast/--best-effort`；
- 验收：构造 12 个失败场景（缺模块、缺符号、坏偏移、坏 ABI、坏动作、坏规则、重复 hook、缺 map、已安装、权限不足、目标退出、架构不符），每个返回唯一错误码且无任何副作用；成功场景 `--check-only` 退出码 0。

### WP2 ABI 与调用约定补全（P0）—— 已完成

- 标量：`int/uint/int64/uint64/pointer/float/double` 参数与返回；动作 `return_float` / `return_double`；BLOCK 动作可声明 `errno` 并由替换回调写回调用者；PASS 路径 `errno` 透传（Linux 已验证；Windows 仍只有 `lastError` 赋值路径）。
- 结构体按值参数与 sret：Frida 无法直接编组，改为 **按签名生成原生 shim**（`runtime/frida/shim.py`）：
  1. bundle 构建期按 spec 生成并编译 `__vg_shim_<n>`（真实结构体类型来自目标头文件/源码）；
  2. 安装期 agent `Module.load` shim，`__vg_shim_bind(program, limit, vg_run)` + `__vg_shim_set_original(target)`，再 `Interceptor.replace(target, shim_entry)`；
  3. shim 把结构体参数按地址、标量按位填入 6 个 VM 槽，调用 VM 判定；BLOCK 执行编译期固定的 `block_c`（如零初始化结构体后返回），PASS 调用原函数。
  4. manifest 中 guard 增加 `shim: {path, entry}`；`load_bundle` 解析路径并校验可选 `sha256`；probe 校验 shim 字段与“shim guard 不支持 observations”。
- 变参函数：`varargs: true` 一律拒绝（`E_ARITY_UNSUPPORTED`），不做 ABI 猜测。
- 已知限制：shim guard 目前不发送 decision 事件、不支持 observers/maps（安装期拒绝）；shim 模块无法卸载（Frida 限制），卸载只恢复原函数。
- 验收：int/int64/pointer/void/float/double 双向、errno 透传/设置、结构体按值 + sret 的 BLOCK/PASS、变参拒绝，均在 WSL 实测通过。

### WP3 动作目录补全（P0）—— 已完成

- 返回类：`return_int/int64/void/null/string/float/double`，均可附带 `errno`。
- 输出参数初始化：`writes` 支持 pointer 类型写 `value: 0`（置 NULL）、`u32/u64` 写 0/常量，可用于初始化多个输出参数。
- 多字段写：同一动作可声明多个 `writes`，按声明顺序执行。
- 资源清理/组合动作：新增 `calls`：`[{module, symbol, args: [{arg: i} | {constant: n} | {string: "..."}]}]`；安装期解析 module/symbol 并构造 `NativeFunction`，BLOCK 时先写字段再调用，最后返回动作值并写 errno。
- 幂等：动作可声明 `once: true`，副作用（`calls`）每个 hook 只执行一次，返回值仍每次都生效；字段写天然幂等。
- 写前安全检查：运行期对每个 `writes` 检查目标指针非空、地址落在 `w` 权限的映射内、`offset+width` 不越界；失败时跳过该写并发送 `action_write_failed:<arg>@<offset>` 诊断，不崩溃。`calls` 异常发送 `action_call_failed` 诊断。
- probe 校验：`calls` 的 module/symbol 可解析、参数引用/常量/字符串合法、`once` 为布尔；否则 `E_ACTION_CALL_INVALID` / `E_ACTION_WRITE_INVALID`。
- 验收：输出指针置 NULL、多字段写、清理函数调用、once 幂等、NULL 目标写失败诊断、probe 非法调用拒绝，均在 WSL 实测通过。

### WP4 生效自证（P0）—— 已完成

- `manifest.smoke` 声明一次触发方式：`{"type": "signal", "signal": "SIGUSR1", "hook": "guard_id", "timeout_ms": 2000}`，也支持 `{"type": "exec", "command": "... {pid} ..."}` 与 `{"type": "none"}`；`run.py`/`multiproc.py` 安装后自动触发并轮询该 hook 的 BLOCK 计数。
- 结果三分：`installed_verified`（观察到 BLOCK）、`installed_unverified`（未声明 smoke，`E_SMOKE_NOT_DECLARED`）、`failed`（声明了但没观察到 BLOCK，`E_SMOKE_FAILED`）。
- 失败策略：默认卸载已装 bundle 并以退出码 9 结束；`--smoke-warn-only` 保留安装、只告警。
- agent 新增 `stats()` RPC，按 hook 返回 `{calls, blocks}`；`install` 回执与 `effect` 一起写入 JSON 输出。
- 限制：shim guard 尚无决策计数（smoke 无法验证 shim 目标）；`exec` 触发命令由补丁作者负责幂等与安全。
- 验收：signal 触发验证 guard、未声明 smoke 记 unverified、PASS-only 补丁被判 failed、CLI 与多进程路径均输出 smoke 状态，均在 WSL 实测通过。

### WP5 多进程与角色（P0）—— 已完成

- **角色推断**（`classify_roles`）：在同一可执行的匹配进程树里，有子进程的根是 master，其余是 worker；`--helper-arg` 指定的命令行子串把进程标成 helper；多个独立 prefork 实例各自识别出 master；单进程应用本身按 worker 处理。
- **选择**：`--role workers|all|master|helpers`（默认 `workers`）；`--pid` 显式指定时不做角色过滤。
- **spawn 模式**：先用 `--spawn-grace`（默认 0.3s）等待 master fork 出 worker；`--role workers` 时跳过 master 但在首轮扫描后恢复它以便 fork；若宽限期内仍无子进程（单进程应用），把被启动进程按 worker 安装。
- **安装窗口**：每次安装记录 `latency_ms`（从首次发现到安装完成）与 `window_exceeded`；`--max-install-latency-ms` 超过阈值时置位并在 summary 累计 `late_installs`。这是**测量**，不是“首请求前完成”的硬保证。
- **重启/重挂**：扫描循环持续安装新出现的进程；`/proc/<pid>/stat` 的 starttime 变化视为 pid 复用（发出 `replaced` 事件并重装）；安装失败按 `--retry-delay`（默认 2s）与 `--max-attempts`（默认 3）退避重试。
- **权限边界**：Yama `ptrace_scope=1` 下只能注入本进程（或 spawn 树）的后代；注入无关进程需要 root/CAP_SYS_PTRACE。
- 验收：`--role workers` 只装 3 个 worker（master 跳过）；`--role all` 装 1 master + 3 worker；respawn 模式下顺序出现的两个 worker 都被重新安装；延迟阈值能标记 `late_installs`。回归脚本：`tests/workloads/userspace/frida/verify_multiproc_roles.sh`。
- 限制：helper 识别依赖命令行标记；“首请求前”只测量不强制；fork 不 exec 的子进程继承 inline hook 的 Frida 限制仍在（本实现只逐进程安装新进程）。

### WP6 线程与并发安全（P0）—— 完成（preload 模式；Frida attach 路径限制已文档化）

已实现并验证：
- **卸载静默**：`runtime/frida/lifecycle.py` 在卸载时轮询 `callbacks active`，等回调退出后再撤销；`run.py`/`multiproc.py` 的卸载路径统一使用它。单元测试覆盖重试、超时、异常传播。
- **线程作用域观测（Frida attach）**：观察点在 pthread 上工作正常；2 线程 telemetry 测试验证“每线程一个 scope/值”。
- **多线程门控（LD_PRELOAD 模式）**：`runtime/preload/build.py` 生成静态链接 `runtime/vm.c` 的原生库，天然线程安全；4 线程 × 25 次调用全部 BLOCK；PASS 经 `dlsym(RTLD_NEXT)` 调原函数；动作写/errno 生效（`tests/test_preload.py`，107 passed）。
- **map 线程作用域（preload）**：观察 wrapper 与 guard wrapper 共用原生 map，scope 取 `pthread_self()`；实测 thread-scoped map 下每线程独立值：2 线程超限被 BLOCK、2 线程放行（`checked_ok=50, checked_blocked=50`，global 语义下会不同）。
- **重入保护**：preload 模式下递归调用经 wrapper→real→递归 PLT 回到 wrapper，`PASS` 规则下递归结果正确（`preload_recurse(4)=4`，无崩溃）；Frida JS 路径保留每线程重入深度实现，但受 replace 回调限制未做递归压测。

Frida attach 路径限制（详见 `docs/ai/FRIDA_THREAD_SAFETY.md`）：
- 非主线程的 replace 回调执行稍复杂 JS/VM 会崩溃或挂起；原生 shim（含静态链接 VM）同样挂起。
- 因此 **Frida attach 模式仅支持主线程/单线程目标**；多线程目标使用 LD_PRELOAD 模式。
- preload 模式只覆盖经过动态符号表（PLT）的调用；观察 map 支持简单 `key_arg`/`value_arg`（无 selector）；静态链接目标不适用。

### WP7 生命周期与失败安全（P1）—— 已完成

- **进程内原子回滚**：agent 先解析全部 guards/observers/动作/规则，再统一替换；任一步失败 `remove()` 撤销已装 hooks。测试：两个 guard 中第二个缺动作 → 安装失败、`status.installed=false`、原函数行为不变、随后可正常安装。
- **卸载 barrier**：`lifecycle.uninstall` 轮询 `callbacks active`，超时由 `--uninstall-timeout-ms`（默认 2000ms）控制；单测覆盖重试、超时与无关异常传播。
- **崩溃隔离**：多进程 launcher 中杀掉一个 worker，仅该 pid 报 `detached`，其余 worker 继续产生 BLOCK；summary 无 failures。回归脚本 `verify_lifecycle.sh`。
- **fail-fast 回滚**：`--fail-fast` 在首次安装失败时中止并卸载全部已装进程，退出码 4；回归脚本验证 `installed=0` 且 summary `fatal` 非空。
- **目标被替换**：`same_image()` 同时比较 starttime 与 exe 真实路径；不一致发 `replaced` 并重装（exec 后 session 断开也会触发重装）。单测覆盖 pid 复用/换镜像；WP5 respawn 集成测试覆盖顺序新进程。
- 验收：上述测试与回归脚本在 WSL 实测通过。

### WP8 观测与运维（P1）—— 已完成

- `runtime/frida/metrics.py`：`EventStream` 把统一事件写成带 `ts` 的 JSONL；`MetricsCollector` 统计 decisions/passes/blocks/observations/diagnostics/reentries，并在**滑动窗口**内诊断数超阈值时打开熔断。
- `run.py` / `multiproc.py` 新增：`--events PATH`（统一事件流）、`--metrics-interval`（周期 metrics 事件）、`--circuit-max-diagnostics`/`--circuit-window-ms`/`--no-circuit-breaker`。
- 熔断行为：命中阈值 → 发送 `circuit-open` → 对**该进程**卸载（`circuit-uninstalled`）→ 记 `E_CIRCUIT_OPEN`、不再重试；launcher 汇总包含 `circuits` 与 `metrics`，退出码 **10**（`EXIT_CIRCUIT`）。
- 验收：单测覆盖计数/窗口过期/阈值/事件流时间戳；live 测试用容量 1 的观测 map 制造 `observation_map_full` 并触发熔断；CLI 端到端验证 `run.py --circuit-max-diagnostics 1` 退出 10 并写出事件流，`multiproc.py` 同样退出 10 且 summary 带 `circuits`。
- 限制：熔断按进程独立；诊断来源为 agent telemetry（decision 的 diagnostic 与 diagnostic 事件），shim guard 暂无 decision 事件。

### WP9 平台与覆盖边界（P1）—— 已完成（文档 + 偏移表工具）

- 支持矩阵、权限模型与交付方式写入 `docs/ai/PLATFORM_AND_LIMITS.md`。
- 新增 `runtime/frida/symbols.py`：从 ELF64 解析 PT_LOAD 基址 + `nm` 符号，生成 `{build_id, load_bias, symbols}` 偏移表；实测对 `frida_fixture` 生成表后用 `offset` 挂点安装并成功 BLOCK。
- 语言边界：C/C++ 支持；Go/Rust 仅偏移级且动作受限；Java/JS/JIT 不支持。
- 明确未实现：ARM64（仅 x86-64）、静态/musl 实测、多线程门控（见 WP6）。

### WP10 交付与集成（P2）—— 已完成

- **bundle 身份**：`runtime/frida/bundle.py` 提供稳定 digest（manifest/catalog/规则/bridge/shim）、`bundle_version` 校验与 HMAC-SHA256 签名；`load_bundle` 在 `VULGATE_BUNDLE_KEY` 设置时强制验签，`bundle_digest` 写入安装回执、事件与 summary；单测覆盖稳定/篡改/缺失签名/版本拒绝。
- **控制通道**：`runtime/frida/control.py`（Unix socket）+ `run.py`/`multiproc.py --control-socket`；`cli.py status/metrics/uninstall --socket` 可对运行中的 launcher 查询与卸载；集成测试验证 status/metrics/CLI metrics/uninstall。
- **CLI**：`cli.py check --pid` 一次性可行性检查；长驻安装由 `run.py`/`multiproc.py` 完成（Frida hook 属于会话，CLI 进程退出即撤销）。
- **权限指南/systemd/容器**：`PLATFORM_AND_LIMITS.md` + `deploy/README.md` + `deploy/vulgate-frida.service`（仅 `CAP_SYS_PTRACE`、`NoNewPrivileges`、控制 socket 与事件日志）。
- 限制：签名为共享密钥 HMAC（非对称签名未做）；未在真实 nginx/httpd/PHP 二进制上执行 WP9/WP10 流程（v1 无 benchmark 构建）。

## 4. 里程碑

| 里程碑 | 内容 | 验收 |
|---|---|---|
| M1 可挂且可解释 | WP1 + WP3 基础 | 12 个错误场景错误码正确；成功场景 `check` 通过 |
| M2 装得上且证明生效 | WP2 + WP4 | 四类签名 + 动作 + smoke 全部通过 |
| M3 生产形态 | WP5 + WP6 + WP7 | fork 型 4 worker 全装；多线程压测通过；卸载/回滚通过 |
| M4 可运维 | WP8 + WP10 | 指标/熔断/签名/权限文档齐备 |

## 5. 测试矩阵

- 合成程序：单进程、fork+exec、fork 不 exec（master/worker）、多线程、热挂、重启、崩溃；
- 真实目标：nginx/httpd/PHP（需在 v1 重建 `build/benchmark20` 二进制）；
- 错误注入：缺模块/缺符号/坏偏移/坏 ABI/坏动作/坏规则/重复 hook/缺 map/权限拒绝/目标退出/架构不符/已安装；
- 长稳：连续安装-卸载 1000 次；24 h 运行无句柄/内存增长。

## 6. 当前实现映射

| 工作包 | 现状 |
|---|---|
| WP1 | 部分：agent 安装前会整体解析并拒绝（已有原子性），但无 `probe` RPC、无错误码体系、无 `--check-only` |
| WP2 | 完成：标量+float/double、errno、结构体按值/sret（原生 shim）、变参拒绝；shim guard 不支持 observers/maps 与 decision 事件（安装期限制） |
| WP3 | 完成：多字段写、输出参数初始化、`calls` 清理/组合动作、`once` 幂等、写前范围检查与诊断、probe 校验 |
| WP4 | 完成：manifest `smoke`（signal/exec/none）、安装后自动触发、`stats()` 计数、`installed_verified`/`installed_unverified`/`failed`、失败卸载与 `--smoke-warn-only` |
| WP5 | 完成：角色推断与 `--role`、spawn 宽限与 master 跳过、安装延迟测量、失败退避重试、starttime pid 复用检测、重启重挂；回归脚本已提交 |
| WP6 | 完成（preload 模式）：卸载静默、多线程 BLOCK、线程作用域 map（50/50 实测）、递归 PASS；Frida attach 路径仅单线程/主线程，限制已文档化 |
| WP7 | 完成：进程内原子回滚、卸载 barrier/超时、崩溃隔离、fail-fast 回滚、starttime+exe 的替换检测；回归脚本已提交 |
| WP8 | 完成：统一事件流、每进程 metrics、滑动窗口熔断与自动卸载、退出码 10；单测与 CLI 端到端验证 |
| WP9 | 完成（文档 + 偏移表工具）：x86-64 实测；stripped 偏移表实测；ARM64/静态链接/多线程明确列为未支持 |
| WP10 | 完成：bundle digest/版本/签名、控制 socket + CLI、权限/systemd/容器文档；签名为 HMAC 共享密钥 |

## 7. 建议执行顺序

1. **WP1**（错误码 + probe + `--check-only`）：后续一切工作的地基，且直接对应用户要求“不能挂就返回错误码并停止”。
2. **WP2 + WP3 + WP4**（ABI/动作/自证）：决定“装了是否真的生效”。
3. **WP5**（角色 + 首请求窗口）：决定真实服务形态可用。
4. **WP6 + WP7**（并发/生命周期）：决定稳定性。
5. **WP8 + WP10**（运维/交付）：决定可交付。

