# 平台、权限与覆盖边界

日期：2026-11-15。本文记录补丁安装器在平台/架构/链接方式/语言上的实际支持范围、权限模型和交付方式。

## 1. 支持矩阵

| 目标形态 | 状态 | 说明 |
|---|---|---|
| Linux x86-64、动态链接、有符号 | ✅ 支持 | 全部 101 项测试与回归脚本在此环境实测 |
| Linux x86-64、stripped / 无导出符号 | ✅ 支持（需偏移表） | `python -m runtime.frida.symbols` 由匹配构建生成 offset 表；manifest 用 `offset` 挂点（已实测） |
| Linux x86-64、静态链接 / musl | ⚠️ 未实测 | 偏移表理论上可用，但 Frida 注入与 TLS/errno 行为未验证 |
| Linux ARM64 | ❌ 未支持 | agent 要求 `Process.arch === 'x64'`；需适配 ABI 上下文与动作返回寄存器（X0–X7/XMM 等价物） |
| Windows x86-64 | ⚠️ 仅 fixture | 现有测试在 Windows 上跑 fixture；真实服务未验证 |
| C/C++ 用户态程序 | ✅ 支持 | 门控、动作、观察、smoke 均按 C ABI 设计 |
| Go / Rust | ⚠️ 受限 | 静态链接、符号少、内联多；只能按偏移挂载，动作受 ABI 限制 |
| Java / JS / JIT 运行时 | ❌ 不支持 | 没有稳定的静态函数入口 |

多线程目标：**Frida attach 模式不支持门控**（Frida replace 回调在非主线程崩溃，见 `FRIDA_THREAD_SAFETY.md`）；**LD_PRELOAD 原生模式已支持多线程门控**（4 线程 × 25 次实测全部 BLOCK，PASS 经 `dlsym(RTLD_NEXT)` 调用原函数），但只覆盖经过动态符号表（PLT）的调用，且当前 preload 模式不支持观察/map。

## 1.1 LD_PRELOAD 模式

```sh
python -m runtime.preload.build --manifest patch/manifest.json --catalog patch/actions.json \
  --output build/libvgpreload.so
LD_PRELOAD=$PWD/build/libvgpreload.so ./target
```

适用于可符号插入的动态链接目标（主程序经 PLT 调用共享库导出函数），支持 return/writes/errno 动作与线程作用域观察 map。静态链接、内部直接调用、selector 型观察暂不支持，需要 Frida 路径或后续扩展。


## 2. 偏移表（stripped 目标）

```sh
python -m runtime.frida.symbols --binary /path/to/target \
  --output build/symbols.json --symbol my_target --symbol my_guard
```

`symbols.json` 含 `build_id`、`load_bias` 与 `symbol -> offset`。manifest 中把 `symbol` 换成 `offset`：

```json
{"module": "target", "offset": 12345, "arg_types": ["pointer"], "return_type": "int", ...}
```

实测：对 `frida_fixture` 生成偏移表后用 `offset` 挂载，调用返回动作值且原函数体未执行。

## 3. 权限模型

Frida 注入需要 `ptrace` 权限：

- **托管启动（推荐）**：launcher 用 `--spawn` 启动目标，目标成为其后代，Yama `ptrace_scope=1` 下无需额外权限；
- **root**：`uid 0` 通常自带 `CAP_SYS_PTRACE`；权限过大；
- **文件能力**：`setcap cap_sys_ptrace+ep /path/to/launcher`（不要给通用解释器授权）；
- **systemd**：`AmbientCapabilities=CAP_SYS_PTRACE`（见 `deploy/vulgate-frida.service`）；
- **容器**：`--cap-add=SYS_PTRACE`，部分 Frida 版本还需 `--security-opt seccomp=unconfined`；
- **不推荐**：`kernel.yama.ptrace_scope=0`（全系统放开）。

安全提示：`CAP_SYS_PTRACE` 等价于可读写同用户进程内存，应按高权限管理（专用账号、最小目标集、审计）。

## 4. 交付方式

- **bundle 身份**：`bundle.py` 提供稳定 digest（manifest/catalog/规则/bridge/shim 全量哈希）、`bundle_version` 校验与 HMAC-SHA256 签名；`load_bundle` 在设置 `VULGATE_BUNDLE_KEY` 时强制验签，并把 `bundle_digest` 写入回执/事件/summary。签名目前是共享密钥 HMAC，后续可换非对称签名。
- **长驻安装**：`run.py`（单进程）或 `multiproc.py`（多进程/角色）常驻，安装才持续有效（Frida hook 属于会话）。
- **控制通道**：launcher 加 `--control-socket /run/vulgate/control.sock` 后，`cli.py` 可执行：
  ```sh
  cli.py status    --socket /run/vulgate/control.sock
  cli.py metrics   --socket /run/vulgate/control.sock
  cli.py uninstall --socket /run/vulgate/control.sock [--pid N]
  ```
  `cli.py check --pid ... --manifest ... --catalog ...` 是一次性可行性检查（不常驻，不能持久安装）。
- **事件/指标**：`--events PATH` 统一 JSONL；`--metrics-interval` 周期指标；熔断阈值见 `--circuit-*`。
- **systemd/容器**：示例 unit 见 `deploy/vulgate-frida.service`，部署说明见 `deploy/README.md`。

## 5. 已知不支持

- 多线程门控（Frida replace 限制）；
- ARM64、JIT 语言；
- 非托管启动且无 `CAP_SYS_PTRACE` 的注入；
- 结构体/sret 之外的自定义 ABI（C++ 异常、变参明确拒绝）。

