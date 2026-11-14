# AutoShield

AutoShield 是“函数入口拦截 + 只读 Shadow eBPF VM”的快速漏洞缓解原型。离线工具生成并验证无副作用的 Shadow 规则；用户态或内核态运行时在目标函数入口执行规则，并返回 `PASS`、`BLOCK` 或 `UNKNOWN`。

## 目录

```text
runtime/
├── autoshield.h             公共数据结构与接口
├── vm.c                     用户态/内核态共享 VM
├── user/                    用户态 hook 与安全内存读取
└── kernel/                  正式通用内核模块
tools/
├── rulegen/                 规则生成、汇编、验证与模板
├── build_kernel_module.sh   内核模块构建入口
└── export_artifacts.sh      PoCLab artifact 导出入口
tests/
├── workloads/userspace/     security 与 perf 测试工作负载
├── test_security.py         攻击阻断与正常放行测试
├── test_robustness.py       verifier 与安全读取测试
└── test_perf.py             性能测试
build/                       所有生成物，不提交 Git
docs/                        设计与开发材料
```

目录边界固定为：`runtime/` 放可部署实现，`tools/` 放开发期工具，测试程序统一放在 `tests/workloads/`。顶层不再维护第二套 `kernel/`、`offline/` 或 `examples/` 实现。

## Frida 用户态挂点

`runtime/frida/` 提供 Frida 函数入口挂载、显式观察映射和原生 VM 桥接。
它加载规则字节码并调用 `runtime/vm.c`；PASS 执行原函数，BLOCK 跳过函数体并执行绑定的返回动作。

```sh
python -m pip install -r requirements-frida.txt
python runtime/frida/build.py --with-fixture
python -m pytest tests/test_frida_backend.py -v
```

测试使用无漏洞的整数计算程序。绑定格式、启动命令及支持范围见
[Frida 后端说明](runtime/frida/README.md)。

## 用户态闭环

依赖 `cc`、`python3`、`make` 和 `pytest`：

```bash
python3 -m pip install -r requirements-dev.txt
make user
make run
make run POC=normal
make copyfail
make test
make test-perf
```

生成物统一位于：

```text
build/workloads/basic/
build/workloads/copyfail/
```

`make run` 会先运行未防护 baseline，再用用户态 hook 加载同一条 Shadow 规则运行 protected case。攻击输入应得到 `decision=BLOCK`，正常输入应得到 `decision=PASS`。

## 通用内核模块

正式模块源码位于 `runtime/kernel/`。它通过模块参数接收目标内核符号，并通过 `/dev/autoshield` 接收已经生成和验证的 Shadow 字节码：

```bash
make kernel-module \
  KERNEL_BUILD=/path/to/configured/kernel/build \
  ARCH=arm64 \
  CROSS_COMPILE=aarch64-linux-gnu-
```

Linux guest 中的部署顺序：

```bash
insmod autoshield.ko target=vulnerable_function block_return=-13
cat shadow.bin > /dev/autoshield
cat /dev/autoshield
```

通用阻断 stub 只适用于返回整数或指针大小值的目标函数；`void` 或结构体返回函数需要类型化 adapter。

## 导出给 PoCLab

AutoShield 与 PoCLab 通过 artifact contract 集成，PoCLab 不依赖这里的源码布局：

```bash
make export \
  SHIELD_MODE=kernel \
  KERNEL_BUILD=/path/to/PoCLab/out/kernel-build-arm64 \
  ARCH=arm64 \
  CROSS_COMPILE=aarch64-linux-gnu- \
  OUT=/path/to/PoCLab/out/arm64/autoshield
```

输出位于 `OUT/kernel/`，至少包含 `autoshield.ko`。如果设置 `AUTOSHIELD_TARGET`，构建工具还会生成对应的 `module.args`。

`docs/human/` 内容必须经过人工确认，不能放完全由 AI 生成的内容。


## v0.2 DSL Policy Bundles

Linux 安全返回候选定位 demo：`python -m tools.frontier --func target --src target.c --src callers.c --json`。用法、证据字段和回归样例格式见 [tools/frontier/README.md](tools/frontier/README.md)。它枚举供审查的入口/返回值，尚不能直接授权内核 ENFORCE。

VulGate v0.2 supports local-only Policy Bundles generated from a restricted DSL:

```bash
make policy
```

Generated artifacts live under `build/policies/<policy_id>/`:

- `policy_manifest.json`
- `policy.ir.json`
- `policy.bin`
- `shadow.c`
- `verify_report.json`

The policy compiler accepts candidate policies written as YAML metadata plus a fenced Python-like DSL block. The DSL primitives are intentionally limited to `@monitor`, `@intercept`, `@check`, `ctx`, `require`, `assert_model`, `assert_action`, `SWRR`, `shadow_call`, and bounded adapters. This keeps LLM-generated policies reviewable and verifiable before runtime use.

Important: policy artifacts and local changes are release-candidate research artifacts only. Do not push, tag, release, or upload local modifications to GitHub unless explicitly requested by the repository owner.
