# VulGate-v1 Frida 版本（单线程/主线程范围）

日期：2026-11-15  
标签：`frida-v1`  
范围：**使用 Frida 后端的热补丁版本**；暂不包含多线程热路径，也不把 native 实验后端作为交付能力。

## 版本内容

- 注入器：Frida（Python），支持 attach/spawn、单进程与多进程 launcher；
- 挂点：`symbol` 或 `offset`，probe/`--check-only` 预检与稳定错误码；
- ABI：int/uint/int64/uint64/pointer/float/double；结构体 by-value/sret 通过生成原生 shim；errno 透传；
- 动作目录：`return_int/int64/void/null/string/float/double`、`writes`、`calls`、`once`、`errno`；
- 生效自证：manifest `smoke` → `installed_verified` / `installed_unverified` / `failed`；
- 多进程：master/worker/helper 角色、只装 worker、spawn 窗口、重启重挂、pid 复用/镜像替换检测；
- 生命周期：原子回滚、`--fail-fast`、崩溃隔离、卸载静默（`callbacks active`）、`--uninstall-timeout-ms`；
- 观测：每进程 metrics、统一 JSONL 事件流（`--events`）、滑动窗口熔断（`--circuit-*`，退出码 10）；
- bundle：schema/digest、`bundle_version`、`VULGATE_BUNDLE_KEY` HMAC 验签、`bundle_digest` 回执；
- 控制通道：launcher `--control-socket`，`cli.py status/metrics/uninstall --socket`；
- 平台/部署：权限指南、systemd 单元、容器说明、stripped 符号偏移表。

## 明确不包含（本版本不声称支持）

- **多线程门控**：Frida 17.26.2 的 replace 回调在非主线程执行复杂 JS 会崩溃/挂起（证据见
  `FRIDA_THREAD_SAFETY.md`）；本版本只覆盖“被补丁函数由主线程/单一调用路径串行调用”的目标；
- native inline/plthook 实验后端（`runtime/native`、`experiments/`）保留在仓库，但不属于本版本交付；
- ARM64/Windows/macOS、真实 nginx/httpd/PHP 的验证；
- 非对称签名（当前 HMAC 共享密钥）；patch 期间新建线程竞态。

## 快速使用

```sh
# 构建后端（Linux）
python -m runtime.frida.build --output build/frida-linux --with-fixture

# 单进程：检查
python runtime/frida/run.py --spawn ./target --manifest m.json --catalog a.json --check-only

# 单进程：安装并在目标退出前保持 attach
python runtime/frida/run.py --spawn ./target --manifest m.json --catalog a.json --duration 10

# 多进程：角色过滤 + 控制 socket + 事件流
python runtime/frida/multiproc.py --spawn ./server --manifest m.json --catalog a.json \
    --role workers --duration 30 --control-socket /tmp/vulgate.sock \
    --events /tmp/vulgate-events.jsonl

# 运行中查询/卸载
python runtime/frida/cli.py status --socket /tmp/vulgate.sock
python runtime/frida/cli.py uninstall --socket /tmp/vulgate.sock
```

详细参数见 `runtime/frida/README.md`。

## 测试证据（WSL Ubuntu-24.04，frida 依赖 `/tmp/vulgate-frida-deps-20261111`）

- Frida 专属测试集合（backend/result/smoke/lifecycle/multiproc/metrics/control/bundle identity）：
  **101 passed in 66.52s**；
- 全仓库测试（含 native 实验）：**120 passed**；
- 集成回归脚本：`verify_multiproc.sh`、`verify_multiproc_roles.sh`、`verify_lifecycle.sh` 均 PASS。

## 已知限制

- 多线程目标请勿使用本版本门控（见上文）；
- 需要 `CAP_SYS_PTRACE` 或托管 `--spawn`；
- shim 的内联 guard 不产生 decision 事件、不支持观察 map；
- 结构体/sret 依赖生成的 native shim（bundle 中 `shim` 字段）；
- `cli.py check --pid` 是一次性探测，持久安装必须由常驻 launcher 完成。
