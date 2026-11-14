# Frida 用户态后端验证记录

日期：2026-11-11。

已实现链路：仓库汇编器生成规则 `.bin` → Frida 安装导出函数入口挂点 →
native bridge 构造 `shadow_ctx` → 原有 `runtime/vm.c::run_ebpf_vm()` →
PASS 执行原函数 / BLOCK 执行动作目录的固定整数返回。

## 环境与结果

| 环境 | 编译器 | Python / Frida | 结果 |
|---|---|---|---|
| Windows 11 x64，10.0.26300 | MSYS2 GCC 15.2.0 | 3.13.9 / 17.26.2 | 10 passed |
| Ubuntu 24.04，WSL2 x64，Linux 6.6.87.2 | GCC 13.3.0 | 3.12.3 / 17.26.2 | 10 passed |

完整测试文件：`tests/test_frida_backend.py`。

Windows 生成物和回执：

- `build/frida/vulgate_frida.dll`
- `build/frida/fixture.manifest.json`、`fixture.actions.json`
- `build/frida/integration-report.json`：逐条调用及 VM 事件。
- `build/frida/pytest-results.xml`：全部测试结果。

Linux 对应文件位于 `build/frida-linux/`，桥接库为 `vulgate_frida.so`。

## 真实执行证据

测试对象是本地无漏洞的整数计算进程，函数体每运行一次增加计数器。
测试通过子进程标准输入让 C 主函数调用目标函数，Frida 拦截实际的 native 调用。

| 操作 | 返回值 | 累计函数体执行次数 |
|---|---:|---:|
| 挂载前调用 `call 1 5` | 105 | 1 |
| 挂载后尚无观察值，调用 `call 1 5` | -73 | 1 |
| 在指定观察点记录键 1 的值为 4，然后调用 `call 1 4` | 104 | 2 |
| 调用 `call 1 5` | -73 | 2 |
| 在指定观察点记录键 2 的值为 9，然后调用 `call 2 5` | 105 | 3 |
| 再调用 `call 1 5` | -73 | 3 |

比较规则的 PASS 和 BLOCK 路径均实际执行 8 条 VM 指令、调用 2 次 helper。
卸载后原函数恢复；重新加载两条指令的 PASS 规则后，同一函数调用改为放行，
VM 报告 2 条指令、0 次 helper。该检查验证决策由加载的字节码驱动。

另外验证：

- 显式更新、删除观察值；不同键隔离；大于 `2^53` 的相邻 64 位键保持区别。
- 原 VM 的 `safe_read_u8` 读取有效字节，空指针读取失败产生诊断并 BLOCK。
- 满表时不自动淘汰记录；删除指定键后可插入新键。
- VM 预算耗尽时使用同一个目录动作。
- 非法字节码在挂载前被拒绝，随后可以正常安装。
- 不支持的 ABI、缺失动作、直接指定返回值及非法预算均被拒绝。
- 启动器脱离仓库工作目录运行，spawn 后在恢复进程前安装挂点，并完成退出清理。

## 本次兼容修正

原 VM 通过 `unsigned long` 转换指针；Windows x64 的该类型只有 32 位。
用户态改用 `uintptr_t`，保留内核态原有指针宽度转换，确保 pointer helper 接收到完整地址。

Linux 启动器测试发现子进程可能在 stdin 结束后自行退出。启动器现在分别记录
“进程终止”和“会话断开”，避免对已经终止的自建进程重复执行结束动作。

## 支持范围

当前为 x64 默认 C ABI、返回 `int`、至多 6 个整数或指针参数的导出函数入口。
观察映射由 Frida agent 管理，值通过 VM 的 `get_reg` 快照槽读取。
动作执行器目前支持 `return_int`。支持 attach 与 spawn、卸载和重新安装。

任意指令地址观察、源码局部变量恢复、输出参数初始化/清理动作、六例 C++/`std::map`
示意的自动编译，以及 VM 有界循环/map 指令扩展，仍是独立的后续接入工作。
上述测试验证运行时挂载链路和对应行为；目标补丁的符号验证仍由已有验证流程负责。

## 复现

```sh
python -m pip install -r requirements-frida.txt
python runtime/frida/build.py --with-fixture
python -m pytest tests/test_frida_backend.py -v --junitxml=build/frida/pytest-results.xml
```

可用 `VULGATE_FRIDA_BUILD` 分离不同平台的测试输出目录，用 `VULGATE_FRIDA_CC`
指定测试编译器。完整绑定说明见 `runtime/frida/README.md`。
