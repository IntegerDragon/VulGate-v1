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

### WP2 ABI 与调用约定补全（P0）

- 参数：x64 SysV 整数/指针（已有）、`float/double`（XMM0–7）、小结构体按值、`sret` 返回结构体、可变参数明确拒绝；
- 返回值：`int/int64/pointer/void`（已有）、静态字符串（已有，需保证生命周期）；
- PASS 路径 `errno`/TLS 错误码透传（Linux glibc/musl 均需）；
- 验收：测试程序覆盖 int/int64/pointer/void/float/double/结构体参数/结构体返回；PASS 后调用者观察到的 errno 与未安装一致；不支持的签名返回 `E_ARITY_UNSUPPORTED`/`E_RETURN_UNSUPPORTED`。

### WP3 动作目录补全（P0）

- 返回类：已有 4 类；
- 输出参数初始化：置 NULL、置 0、置空串，多参数；
- 多字段写：已有单字段；扩展到同一动作多个写入、写入前安全检查（非空/可写/宽度）；
- 资源清理：解锁、关 fd、释放/减引用（需逐应用定义，动作目录声明）；
- 调用既有错误路径：跳转到函数内已有错误标签（可行则做，不可行则明确不支持）；
- 幂等性：同一函数重复 BLOCK 不产生累计副作用；
- 验收：每类动作有单元测试 + 安装后触发测试；动作写越界/空指针时行为是拒绝安装（`E_ACTION_WRITE_INVALID`）而不是运行时崩溃。

### WP4 生效自证（P0）

- `manifest.smoke`：声明触发方式（命令行 stdin 行、HTTP 请求、C 调用、文件输入）；
- 安装后自动执行一次，检查 `BLOCK` + 动作返回值；记录到 receipt `effect`；
- 无 smoke：`installed_unverified`；smoke 失败：`failed` + `E_SMOKE_FAILED`（可配置为仅告警）；
- 验收：有/无/失败三种状态可区分；smoke 不修改目标持久状态（或声明并清理）。

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
| WP2 | 部分：整数/指针/四类返回；缺 float/struct/sret/errno |
| WP3 | 部分：四类返回 + 单字段写；缺输出参数初始化/资源清理/组合/幂等 |
| WP4 | 缺：无 smoke、无 `installed_verified` 区分 |
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
