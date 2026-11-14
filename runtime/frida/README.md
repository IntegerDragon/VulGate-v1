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
