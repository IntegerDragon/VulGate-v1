# 用户态补丁安装可用性：现状与后续工作

日期：2026-11-14。范围：只讨论“给定补丁（挂载位置 + 行为）+ 目标应用，在任意用户态目标上安装并生效”，不含符号执行与补丁正确性验证。

## 1. 目标与最小契约

一次“可用”的安装必须同时满足：

1. **定位**：从目标二进制中唯一确定挂载点（模块 + 符号或模块 + 偏移），并验证目标身份（路径、构建号/哈希）。
2. **安装**：在目标进程内建立门控，替换目标函数的返回或写入约定字段；每个进程独立回执。
3. **生效**：安装后至少触发一次 `BLOCK` 的实测证据；只有安装回执而没有触发证据时，报告必须写 `installed_unverified`。
4. **撤销**：卸载后目标函数恢复原行为，进程继续正常运行。
5. **多进程**：master/worker（nginx、httpd prefork、PHP-FPM）中的每个工作进程都被安装，主进程不误装。
6. **失败安全**：目标不匹配、符号缺失、ABI 不符、注入失败时拒绝安装并清理已装部分。

## 2. 本次已完成并验证

- `runtime/frida/multiproc.py`：按 `--exe` / `--name` 扫描 `/proc`，或 `--spawn` 托管启动并跟随后代；对每个新进程独立 attach、安装、回执；结束时统一卸载并打印 `summary`。
- `tests/workloads/userspace/frida/forker.c` + `verify_multiproc.sh`：父进程 fork+exec 出 3 个 worker，worker 循环调用目标函数。实测父进程 + 3 个 worker 共 4 个进程全部安装；worker 返回值从 42 变为动作目录的 -73，卸载后恢复。
- `tests/test_frida_multiproc.py`：进程发现、匹配、自我排除的单元测试（Linux）。
- 已知平台约束：Yama `ptrace_scope=1` 下只能注入本进程启动的进程树；注入已运行进程需要 root 或 `CAP_SYS_PTRACE`。fork 后不 exec 的子进程会继承 inline hook，Frida 不保证继承后的钩子可用。

## 3. P0：决定“任意目标可装且生效”

### 3.1 目标与挂点解析

- 符号优先（`module + symbol`），无符号时用 `build-id -> offset` 离线表（构建期生成，随二进制哈希钉死）。
- 模块解析覆盖主程序、共享库、运行期 `dlopen` 的模块；同名模块要按路径区分。
- 拒绝内联/被合并的函数：要么自动上移挂到保留的外层函数，要么明确报错。
- 安装前校验目标路径、`build-id` 或哈希；不匹配拒绝安装。
- 验收：对 stripped、`-O2` 构建的真实程序能绑定至少一个挂点；错误目标/错误偏移给出可读错误且不残留 hook。

### 3.2 进程角色与安装时机

- 区分 master / worker / helper：`--exe` 扫描到的进程不能全部安装；需要角色规则（ppid、命令行、进程树层级、cgroup）。
- master 不安装，只安装 worker；worker 由 master `fork`（nginx）或 `fork+exec`（httpd prefork 的某些配置）。
- 安装时机：尽量在 worker 接受首个请求前完成。可用的工程手段：
  1. 暂缓 worker 的请求入口（例如临时挂 accept/读取入口，安装完成后再放行）；
  2. 由 launcher 托管启动，快速扫描（10–20 ms）；
  3. 接受安装窗口，但在回执里记录窗口长度。
- 验收：nginx `worker_processes 4` 下 4 个 worker 全部安装、master 未安装；首个外部请求前完成（或明确记录窗口）。

### 3.3 ABI 与行为

- 参数：已支持 x64 SysV 的整数/指针（≤6 个）；需要浮点（XMM）、结构体参数、结构体返回值（sret）；可变参数明确拒绝。
- PASS 路径的 `errno`/TLS 错误码透传（当前只在部分路径保存）。
- 动作目录补齐：输出参数初始化（置 NULL/0）、多字段写、资源清理（解锁、关 fd、减引用）、幂等（重复 BLOCK 不累计副作用）。
- 验收：int/int64/pointer/void 四类返回在测试程序上安装并正确返回；errno 保留；动作重复触发不产生额外副作用。

### 3.4 生效自证

- manifest 增加可选 `smoke` 触发项（协议请求、stdin 行、C 调用）；安装后自动执行一次并检查 `BLOCK` 与动作返回值。
- 无触发项时报告 `installed_unverified`，不冒充“已生效”。
- 验收：触发项成功时回执包含 `decision=BLOCK` 与动作值；未提供触发项时状态字段明确。

### 3.5 生命周期与失败安全

- 安装中途失败回滚（当前 agent 的 `install` 已做 `remove`，需要补多进程层面的部分失败处理）。
- 运行期卸载：agent 要求 `active === 0`，热卸载需要通过 `barrier` 等待静默或返回 `busy`。
- 目标重启：`--exe/--name` 扫描自动重装（已具备），需要有上限与退避，避免崩溃循环。
- 验收：杀死一个 worker 后新 worker 自动安装；卸载后调用恢复原结果；目标反复重启不导致 launcher 卡死。

## 4. P1：规模化与可运维

1. 目标发现配置：systemd unit、cgroup、容器（PID namespace）里的进程发现与角色规则。
2. 事件与指标：每进程 decisions/blocks/诊断/安装延迟，统一事件流与导出。
3. 补丁包格式：manifest + actions + bridge + 触发项版本化、哈希、签名；目标哈希白名单。
4. 跨平台：Linux x86-64 先行；Windows 目标需要匹配目标架构的 Frida 与模块/符号解析差异。
5. CLI 体验：`--check-only`（只解析不安装）、`--dry-run`、明确错误码。

## 5. P2：生产化

1. 权限最小化：非 root 方案（`setcap cap_sys_ptrace+ep`、Yama 策略、SELinux/AppArmor 规则）。
2. 熔断与回滚：安装失败/异常决策率超阈值自动卸载；灰度与 kill switch。
3. 性能与稳定性：BLOCK 全命中时的吞吐/尾延迟压测；长时间运行的内存与句柄泄漏检查。
4. 构建集成：自动产出 `build-id -> offset` 表、结构体 layout、动作目录候选。

## 6. 建议的下一步（按投入产出）

1. **角色感知安装**：给 multiproc 增加 `--role`（master/worker）与排除规则，先用一个 fork 型 server 验证（nginx 的 master/worker 模型）。
2. **安装窗口**：worker 首请求前完成安装的机制（临时阻塞入口 + 安装完成后放行），并记录窗口。
3. **生效自证**：manifest `smoke` + 安装后自动触发，回执区分 `installed_verified` / `installed_unverified`。
4. **挂点解析回退**：符号缺失时的 build-id 偏移表，先覆盖一个 stripped 构建的目标。
