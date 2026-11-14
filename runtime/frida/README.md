# VulGate Frida 用户态后端

Frida 在指定导出函数入口挂点，原生 bridge 直接调用 `runtime/vm.c` 的
`run_ebpf_vm()`。PASS 调用原函数一次；BLOCK 跳过原函数，执行动作目录中绑定的
`return_int`。动作目录与规则文件分开提供。字节码从 `.bin` 加载并由现有 VM 校验器检查。

```text
显式观察函数入口 → 按参数键保存当时的参数值
目标函数入口 → 参数和指定观察快照 → bridge → 原有 eBPF VM
                                              ├─ PASS → 原函数
                                              └─ BLOCK → 绑定的 return_int
```

## 构建与验证

依赖 Python、Frida 和 GCC/Clang；动态库与目标进程必须同为 x64。

```sh
python -m pip install -r requirements-frida.txt
python runtime/frida/build.py --with-fixture
python -m pytest tests/test_frida_backend.py -v
```

Windows 可以通过 `--cc C:/msys64/mingw64/bin/gcc.exe` 指定编译器。
生成物在 `build/frida/`，包括 bridge、agent、启动器、示例规则和绑定配置。
测试只运行 `tests/workloads/userspace/frida/fixture.c`：它计算整数并增加函数体计数器。

2026-11-11 实测：Frida 17.26.2，Windows 11 x64 与 Ubuntu 24.04 / WSL2 x64
各通过 10 项测试。详细过程见 `docs/ai/FRIDA_BACKEND_VALIDATION.md`。

## 挂载

```sh
python build/frida/run.py --pid PID \
  --manifest build/frida/fixture.manifest.json \
  --catalog build/frida/fixture.actions.json
```

也可以用 `--spawn /absolute/path/to/application` 在新进程恢复执行前安装挂点。
启动器保持连接，Ctrl+C 卸载；`--duration 5` 可指定连接时长。
`--spawn` 启动的进程由启动器管理，退出时结束该进程；`--pid` 不结束已有进程。

`fixture.manifest.json` 是绑定示例，更换目标程序时填写实际模块、导出符号和精确参数类型。
`guards[].rule` 相对于 manifest 所在目录；`action_id` 引用独立目录中的固定返回动作。
桥接库是本地路径，当前启动器连接本机进程。

## 观察与规则输入

`observers` 指定 `module/symbol`、`arg_types`、`key_arg` 以及 `value_arg`。
`set` 只读取该入口时刻的参数，保存一个 64 位值；`delete` 在另一个显式挂点删除键。
`guards[].observations` 指定 map、当前调用的键参数，以及 VM 的快照槽 `slot`。
规则通过已有 `get_arg` 读取当前参数，通过 `get_reg` 读取快照槽；本后端的槽不是机器寄存器。
`safe_read_u8` 在规则执行时读取当前指针指向的一个字节。

示例 `observed_limit.asm` 比较参数 1 和槽 0，`read_byte.asm` 比较读到的字节与 7。
两者均由仓库现有汇编器生成 `.bin`，加载后运行原生 VM，没有在 JS 中硬编码比较策略。
修改规则并重新加载即可改变决策，不需要重新编译 bridge。

映射按显式键共享，不自动推断线程、调用实例、对象代次或生命周期。
绑定负责选择键、更新时机和删除点；槽内容始终是已记录的快照。
映射有容量限制，不自动淘汰旧键；满表时报告诊断，新键没有快照。
缺少所需快照、读取失败或 VM 预算耗尽时执行同一个绑定 BLOCK 动作并记录诊断。
对外策略动作只有 PASS/BLOCK；原 VM 的 UNKNOWN/VM_ERROR 保留为内部诊断码。

## 当前边界

- 挂点是导出函数入口；未实现任意指令位置、DWARF 局部变量解析或源码行自动绑定。
- 支持默认 x64 C ABI，返回 `int`，至多 6 个 `int/uint/int64/uint64/pointer` 参数。
  浮点、结构体、可变参数和其他调用约定需要新增适配。
- 当前动作目录执行器只支持 `return_int`；需要输出参数初始化或资源清理的返回动作尚未接入。
  候选点和返回值由已有分析流程给出，本后端不重新证明该点的提前返回契约。
- 本实现不会把之前的六例 C++/`std::map` 示意自动编译成字节码，也没有扩展 VM 的循环或 map 指令集。
- 安装、卸载时应让目标调用静止。RPC 卸载检测仍在执行的 guard，避免释放活跃 VM 句柄。
  挂点安装前的历史事件不能从观察映射中恢复。
- PASS 复制原调用返回的 errno/LastError；尚未为依赖入口 TLS 错误码的函数提供完整保存契约。
- Windows、Linux、macOS 各有内存读取实现；实测平台和版本见测试回执。

导出可运行包：`make export-frida`。脱离源码目录运行时，使用包内的 `run.py`、manifest 和动作目录。

## 多进程安装

`runtime/frida/multiproc.py` 把同一份补丁分别安装到每个匹配的进程，适合
master/worker 模型（nginx、httpd prefork、PHP-FPM）：

```sh
# 由本进程托管启动目标，并跟随它 fork/exec 出的子进程
python -m runtime.frida.multiproc --manifest M --catalog C \
  --spawn /usr/sbin/nginx --arg -g --arg 'daemon off;'

# 周期性扫描 /proc，把补丁装到之后才出现的进程
python -m runtime.frida.multiproc --manifest M --catalog C \
  --exe /usr/sbin/nginx --interval 0.02 --duration 30

# 直接指定若干个进程
python -m runtime.frida.multiproc --manifest M --catalog C --pid 1234 --pid 1235
```

- 每个进程独立会话、独立字节码句柄、独立安装回执；结束时打印 `summary` 并卸载。
- 角色：默认 `--role workers`，按进程树推断 master/worker，master 跳过；`--role all|master|helpers` 可选，`--helper-arg` 标记 helper 进程。
- spawn 模式用 `--spawn-grace`（默认 0.3s）等 master fork 出 worker；单进程目标在宽限期后按 worker 安装。
- 每次安装输出 `latency_ms` 与 `window_exceeded`；`--max-install-latency-ms` 设阈值，失败按 `--retry-delay`/`--max-attempts` 退避重试，pid 复用/镜像变化按 starttime+exe 检测并重装。`--fail-fast` 在首次失败后回滚全部，`--uninstall-timeout-ms` 控制卸载等待回调静默的时长。
- 进程权限：Linux Yama `ptrace_scope=1` 时只能注入本进程启动的进程树；注入已运行进程需要 root 或 `CAP_SYS_PTRACE`。
- fork 后不 exec 的子进程会继承 inline hook，Frida 不保证继承后的钩子可用；这类目标应由 launcher 启动并在 worker 出现时逐个安装，或由目标 exec 出 worker。
- 回归脚本：`bash tests/workloads/userspace/frida/verify_multiproc.sh`（Linux，需 frida Python 模块）。

## 安装前检查

`--check-only` 只解析 bundle、不挂载任何 hook，返回每个进程的绑定结果与错误码：

```sh
python -m runtime.frida.run --pid PID --check-only --manifest M --catalog C
python -m runtime.frida.multiproc --exe /usr/sbin/nginx --check-only --manifest M --catalog C
```

退出码：0 通过、2 参数错误、3 bundle 无效、4 挂点不可挂、5 权限/注入失败、6 目标不匹配、7 部分失败、8 已安装、9 smoke 未生效。错误码表见 `docs/ai/PATCH_INSTALL_NEXT_STEPS.md`。

## 生效自证

manifest 可声明一次 smoke 触发：

```json
{"smoke": {"type": "signal", "signal": "SIGUSR1", "hook": "guard_id", "timeout_ms": 2000}}
```

安装后 launcher 触发目标并检查该 hook 的 BLOCK 计数：观察到即 `installed_verified`，未声明为 `installed_unverified`，声明但未观察到为 `failed`（`E_SMOKE_FAILED`）。失败默认卸载并以退出码 9 结束；`--smoke-warn-only` 保留安装并告警。也支持 `{"type": "exec", "command": "... {pid} ..."}` 与 `{"type": "none"}`。



