# 服务器测试工作流（qizhi-51）

日期：2026-11-15  
约定：**本任务后续的代码运行与测试都在服务器 `/kyz/VulGate-v1` 进行，不再使用 WSL。**

## 主机与连接

- SSH 别名：`qizhi-51`
- 连接方式：`ProxyJump zhipu-server-kvm`，跳板后 `127.0.0.1:22251`，用户 `root`
- 实际主机名：`qb-prod-gpu4090`
- 系统：Ubuntu 24.04，x86_64，内核 6.8，gcc 13.3，cmake 3.28，Python 3.12

## 代码位置与依赖

```text
/kyz/VulGate-v1          # 本任务专属目录
/kyz/VulGate-v1/.venv    # pytest 9.2 + frida 17.26.2 + pyelftools
/kyz/VulGate-v1/build    # 构建产物（不提交）
```

## 同步代码

本地修改 → commit → push 到 GitHub；服务器拉取：

```sh
ssh qizhi-51 "cd /kyz/VulGate-v1 && git pull --ff-only origin main"
```

（服务器 clone 使用 HTTPS 只读；提交与推送仍从本地执行。）

### 未提交改动的快速同步（本地 → 服务器）

修改后、提交前想先在服务器跑测试，可用：

```powershell
python tools/sync_to_qizhi51.py
```

脚本把本地工作树（排除 `.git/`、`build/`、`.venv/`、缓存目录）打包，经 `scp` 传到
`qizhi-51:/tmp`，在 `/kyz/VulGate-v1` 解包；文本文件统一转成 LF，避免 Windows CRLF 把服务器
git 工作区弄脏。它**不更新服务器 git HEAD**：验证通过后仍建议 commit + push，再在服务器
`git pull --ff-only` 归一化。

## 构建 Frida 后端

```sh
ssh qizhi-51 "cd /kyz/VulGate-v1 && \
  .venv/bin/python -m runtime.frida.build --output build/frida-linux --with-fixture"
```

## Frida 测试

```sh
ssh qizhi-51 "cd /kyz/VulGate-v1 && \
  .venv/bin/python -m pytest \
    tests/test_frida_backend.py tests/test_frida_result.py tests/test_frida_smoke.py \
    tests/test_frida_lifecycle.py tests/test_frida_multiproc.py tests/test_frida_metrics.py \
    tests/test_frida_control.py tests/test_frida_bundle_identity.py -q"
```

最近一次服务器实测（2026-11-15）：**101 passed in 21.84s**。

## DSL 补丁验证

```sh
ssh qizhi-51 "cd /kyz/VulGate-v1 && \
  .venv/bin/python -m pytest tests/test_dsl.py -q && \
  .venv/bin/python -m runtime.dsl.validate20 --json /tmp/dsl20.json"
```

最近一次服务器实测（2026-11-16）：DSL 单测 **5 passed**；20 个 CVE 的 DSL
**28/28 block/pass/memory 场景通过**。详见 `runtime/dsl/README.md`。

> 说明：`runtime/native` 的 plthook/inline 实验测试需要额外的 plthook/funchook 源码目录，服务器当前未安装，
> 因此不属于本 Frida 版本的验证范围；需要时再单独准备依赖。

## 注意事项

- 服务器上不要修改 git 历史；所有提交在本地完成后 push，再由服务器 pull。
- `build/`、`.venv/` 不提交。
- 多线程门控不在 Frida 版本支持范围内（见 `FRIDA_RELEASE.md`）。
