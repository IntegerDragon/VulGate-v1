# 第六例 PHP session 补丁：正常功能误伤实测

日期：2026-11-12。

使用此前六例中的第六个补丁，即 `06_php_session.bpf.cpp`：在 `php_session_rfc1867_callback` 入口对全部事件执行 BLOCK，由动作目录返回 PHP `SUCCESS`。本次没有改变原策略的拒绝条件。

结论：普通文件上传正常，依赖 session upload-progress 的功能丢失。18 个正常功能用例中，6 个普通表单和 6 个普通上传结果不变；6 个要求上传进度的用例全部出现可观察差异。

## 1. 真实目标与配置

- 会话原条目标识：CVE-2026-109619。
- 原版：`php/php-src@dd830558ffb1ac8378e812b4db97626e6087de3f`。
- 官方修复版：[31c0ea7d7ff1d1fccb6492e52dab544011628065](https://github.com/php/php-src/commit/31c0ea7d7ff1d1fccb6492e52dab544011628065)。参考程序使用该提交的完整构建，包含共享修复的依赖。
- 实际版本输出为 PHP 8.5.12-dev、NTS。使用真实 PHP 内置 HTTP 服务、multipart 解析器和 session 模块。
- 快速补丁由 Frida 安装到原版进程的实际 callback 入口，固定字节码交给现有 VM 执行。
- 三个进程具有相同功能配置和独立的 session 保存目录；每个用例使用新的 session ID。
- 开启 `session.upload_progress.enabled=1`，设置 `session.upload_progress.cleanup=0`，使完成后的进度记录可被应用读取和比较。此配置使测试不依赖实时轮询时机。
- `session.upload_progress.freq=1`、`session.upload_progress.min_freq=0`；不加载外部 php.ini。

首个请求前检查 NTS 构建、原 callback 链为空、当前注册 callback 正是 session callback、progress 指针为空。worker 由实验器新启动，检查和安装之前只进行 TCP 监听就绪检查，没有发送应用请求。

## 2. 用例与功能契约

测试程序 `experiments/postdeploy/php_session/router.php` 输出普通表单字段、上传文件的名称/大小/错误码/SHA-256，以及 session 中上传进度记录的存在性、完成状态、文件数量和处理字节数。

| 类别 | 数量 | 原版 | 快速补丁版 | 官方修复版 |
|---|---:|---|---|---|
| 普通 URL-encoded 表单 | 6 | 正常 | 正常 | 正常 |
| 不要求进度记录的 multipart 文件上传 | 6 | 文件正确 | 文件正确 | 文件正确 |
| 要求 session upload-progress 的文件上传 | 6 | 文件正确，进度完整 | 文件正确，进度缺失 | 文件正确，进度完整 |

上传文件大小为 0、1、32、256、4096、32768 字节。所有请求均为普通编码的表单和文本文件，所有 session 都从空状态开始。

本组语料有 6/18 个用例出现功能差异；进度功能类别为 6/6。这个比例描述本次分组语料，不代表部署流量中的误伤率。

## 3. 一个实际请求的结果

case 16 上传 4096 字节文本文件：

| 可观察量 | 原版 | 快速补丁版 | 官方修复版 |
|---|---:|---:|---:|
| HTTP 状态 | 200 | 200 | 200 |
| 上传文件大小 | 4096 | 4096 | 4096 |
| 上传错误码 | 0 | 0 | 0 |
| 文件 SHA-256 | 三方一致 | 三方一致 | 三方一致 |
| `progress_present` | true | **false** | true |
| `progress_done` | true | **null** | true |
| `progress_file_count` | 1 | **0** | 1 |
| `progress_bytes` | 4476 | **null** | 4476 |

`progress_bytes` 包含 multipart 请求的表单与边界开销，因此大于文件大小。

这里的 BLOCK 表示跳过 session 进度回调正文。动作返回 `SUCCESS`，上传解析器继续运行，所以 HTTP 成功和文件正确不能代替进度功能检查。

## 4. Monitor、覆盖与 VM 结果

- 18 组、三方共 54 次 HTTP 请求完成。
- 88 次实际 VM 判定，均为 BLOCK；全部快照重放一致；诊断为 0。
- 字节码与固定判定摘要的 CBMC 检查通过，377 项属性完成检查。
- 原版与快速补丁版的 18 个 trace 全部完整。
- `session.c` 覆盖边从 730 降到 315，消失 415 条，执行序列变化的用例为 12 个。
- 固定构建上的安装、VM 摘要验证和三方重放耗时约 5.74 秒，源码下载与构建不计入其中。
- 相关回归测试合计 18 项通过：Frida / postdeploy 测试首次完成 16 项，配置 CBMC 后另外 2 项符号测试通过（算术影响发现、跳过输出初始化的差异检测）。

分组覆盖结果：

| 类别 | 原版边数 | 补丁版边数 | 执行序列改变 | 功能结果改变 |
|---|---:|---:|---:|---:|
| 普通表单 | 315 | 315 | 0/6 | 0/6 |
| 普通上传 | 361 | 310 | 6/6 | 0/6 |
| 要求进度的上传 | 712 | 310 | 6/6 | 6/6 |

这次实验同时展示了两点：只检查 HTTP 状态会漏掉进度功能损失；只根据覆盖变化判定误伤，会把功能保持正常的普通上传也标为失败。应由覆盖变化定位需要检查的区域，再由业务输出契约判定功能影响。

## 5. 本次使用的验证范围

本次直接运行完整 PHP HTTP 请求，复用了通用 Frida 安装器、原生 VM、快照重放 Monitor、配对覆盖统计及 CBMC VM 摘要验证。

PHP 请求状态的成对符号执行尚未接入；本次的功能差异来自真实三方请求执行。报告中的 `symbolic_scope` 明确记录为 VM 字节码摘要范围。覆盖只对真实 `ext/session/session.c` 插桩，不把该文件的覆盖数量解释为整个 PHP 程序覆盖率。

在需要保留上传进度的应用契约下，此补丁存在已实测的功能误伤；它保留了普通表单和文件上传。若应用接受停用进度功能，则属于明确的功能降级策略，验收规格应单独表达这一选择。

## 6. 代码、证据和复现

代码：

- `experiments/postdeploy/php_session/build.py`：固定两版源码和构建；只对 session.c 插桩。
- `experiments/postdeploy/php_session/run.py`：原第六例策略、18 个正常用例、三方对照、机器报告。
- `experiments/postdeploy/php_session/router.php`：独立的应用功能观察。
- `tools/postdeploy/http_process.py`：通用本地 HTTP 进程适配器，首个请求前安装、覆盖记录、事件同步。

证据目录：`build/postdeploy-php-session/run-01/`，包含 `report.json`、`coverage.json`、三份安装回执、构建来源、每例三方输出/trace/VM 事件和 VM 摘要求解证据。

工作区归档：`D:/Codex/2026-11-03/goal-042fb9fb-01ec-4a00-960b-c95a63665f9e/outputs/postdeploy-php-session-20261112/`。归档保存本报告、完整运行证据与原第六例策略，`integrity.json` 记录归档时对 12 个输入文件的 SHA-256 核对结果。运行证据中的绝对路径保留实际执行时的 WSL 路径。

Linux 仓库根目录执行：

```bash
python3 -m pip install -r requirements-postdeploy.txt
python3 -m runtime.frida.build --output build/frida-linux
python3 experiments/postdeploy/php_session/build.py
python3 experiments/postdeploy/php_session/run.py \
  --output build/postdeploy-php-session/run-new \
  --cbmc /absolute/path/to/cbmc
```

构建还需要 GCC、make、autoconf、bison、re2c、pkg-config。源码构建默认位于 `/tmp/vulgate-php-session-20261112`，生成的二进制和构建记录复制回仓库的 build 目录。

本机 WSL 的 Python 依赖位于 `/tmp/vulgate-frida-deps-20261111`，命令通过 `PYTHONPATH` 使用该目录。
