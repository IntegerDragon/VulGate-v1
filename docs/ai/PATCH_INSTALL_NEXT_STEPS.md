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

### WP5 多进程与角色（P0）

- 角色识别：master / worker / helper（ppid、命令行、进程树层级、可配置规则）；
- 默认只装 worker；master 跳过并记录；
- 首请求前窗口：暂缓 worker 请求入口（如临时挂 accept/read 入口）→ 安装完成 → 放行；或快速扫描并记录窗口长度；
- fork 不 exec 场景：不依赖继承 hook，逐进程安装；检测已继承的 Frida 状态并拒绝/重装；
- 重启重挂：新 worker 自动安装，带退避与上限；pid 复用检测；
- 验收：fork 型 master/worker 测试程序（4 worker）全部安装、master 不装；首请求前完成或窗口有记录；kill worker 后新 worker 自动安装。

### WP6 线程与并发安全（P0）

- 替换期间的静默：定义 `Interceptor.replace` 与并发调用的关系，必要时用 `barrier`/暂停窗口；
- 多线程并发命中：决策计数、map 线程作用域、无数据竞争（桥内状态需线程安全或按线程隔离）；
- 重入：hook 调用的函数又被同一 hook 命中时的递归保护；
- 验收：多线程压测（≥8 线程、≥100k 次调用）无崩溃、无丢失决策、计数一致。

### WP7 生命周期与失败安全（P1）

- 部分安装失败回滚（已有 agent 内 `remove`，需覆盖 probe 后安装阶段）；
- 卸载：`barrier` 等静默，超时返回 `E_TARGET_BUSY`；
- 目标崩溃隔离：一个进程崩溃不影响 launcher 与其他进程；
- 目标被替换（`/proc/pid/exe` 指向 `(deleted)`）与 pid 复用；
- 验收：注入中途杀目标不留残留；卸载后调用恢复原行为；单进程崩溃其他进程继续。

### WP8 观测与运维（P1）

- 每进程指标：decisions/blocks/diagnostics/安装延迟/窗口；统一事件流（JSON lines）；
- 熔断：map 满、VM 步数超限、未知写、诊断速率超阈值 → 自动卸载并告警；
- 日志与审计：谁、何时、对哪个 build-id、装了哪些 hook；
- 验收：指标可导出；熔断触发后目标恢复原行为；审计记录包含 pid/build-id/时间。

### WP9 平台与覆盖边界（P1）

- x86-64 Linux：本轮完成；
- ARM64：Frida 支持，但 SysV ABI（x0–x7）、返回值替换、汇编桩需重做，列为后续；
- 静态链接/musl/stripped：挂点靠 build-id→offset 表（源码一致前提下可由构建产出），列为后续；
- 语言边界：C/C++ 支持；Go/Rust（符号少、内联多）仅偏移级且动作受限；Java/JS/JIT 不支持（明确写进文档）。

### WP10 交付与集成（P2）

- bundle 格式版本化与签名；目标身份校验（build-id/哈希）；
- CLI 完整：`install/uninstall/status/check`、`--dry-run`、`--fail-fast`、`--summary`；
- 权限指南：托管启动（无特权）/ root / `setcap cap_sys_ptrace+ep` / systemd `AmbientCapabilities` / 容器 `--cap-add=SYS_PTRACE`；
- systemd/容器集成与重启策略；
- 验收：一条命令完成“检查→安装→触发→卸载”，退出码与错误码稳定。

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
| WP5 | 部分：multiproc 扫描/跟随/逐进程安装已实现并验证；缺角色识别与首请求窗口 |
| WP6 | 未知：无并发压测，桥状态线程安全未验证 |
| WP7 | 部分：agent 安装失败回滚；缺卸载静默/崩溃隔离/pid 复用 |
| WP8 | 部分：每进程 decisions/blocks 计数；缺统一指标/熔断/审计 |
| WP9 | 仅 x86-64 Linux；其他边界仅文档 |
| WP10 | 部分：install/uninstall/status；缺 check/dry-run/签名/权限指南 |

## 7. 建议执行顺序

1. **WP1**（错误码 + probe + `--check-only`）：后续一切工作的地基，且直接对应用户要求“不能挂就返回错误码并停止”。
2. **WP2 + WP3 + WP4**（ABI/动作/自证）：决定“装了是否真的生效”。
3. **WP5**（角色 + 首请求窗口）：决定真实服务形态可用。
4. **WP6 + WP7**（并发/生命周期）：决定稳定性。
5. **WP8 + WP10**（运维/交付）：决定可交付。
