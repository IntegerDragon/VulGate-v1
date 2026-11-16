# DSL→VM 性能结果（真实应用）

## 结论先行

本次性能结论只使用**真实 nginx 1.31.6**，不再用合成 fixture 推导性能。

```text
baseline RPS 中位数: 974.34
VM RPS 中位数:       864.97
RPS 变化:            -11.2%
p95:                 70.82 ms → 78.43 ms
p99:                 98.76 ms → 103.13 ms
```

合成 fixture 只保留为功能验证（VM 条件、ABI、map/callsite/DWARF），
不作为性能结论依据。

## 测试环境

```text
host: qizhi-51, Linux x86-64
nginx: 1.31.6, master_process off
injector: Frida 17.26.2 / Python 3.12
请求: GET /rewrite/ordinary
补丁: CVE-2026-42945
负载: 32 线程闭路，5 s 采样
```

## 方法

- baseline / VM 交替执行；
- 各跑 **5 次**；
- 取中位数，并给 min–max；
- 每次前 warm-up；
- VM 安装后等待 2 s 稳定，patch 自然结束；
- 不使用 `pkill` 强行结束，避免 Frida detach 破坏 nginx；
- 未做 CPU 绑核，机器噪声仍存在。

## 结果

| 模式 | RPS 中位数 | RPS min–max | p95 中位数 | p99 中位数 | 状态 |
|---|---:|---:|---:|---:|---|
| baseline | 974.34 | 900.77–1045.92 | 70.82 ms | 98.76 ms | 302 |
| VM | 864.97 | 853.58–975.07 | 78.43 ms | 103.13 ms | 500 |

解读：

- baseline 自身波动约 ±7%，因此不能用单次结果；
- VM 中位数约 **-11.2% RPS**；
- p95 约 **+7.6 ms**；
- 该补丁把 302 改成 500，业务路径本身不同，所以 RPS 差异不等同于纯 hook 开销；
- 但 VM 和 baseline 的差距在 5 次中都存在，方向稳定。

## 未测 / 不可测

- PASS 路径在真实 nginx 上挂住；
- 多线程 Frida 回调挂住；
- 真实 PHP / httpd / brotli 目标不在清理后的仓库/服务器中，未接入；
- nginx 未 CPU 绑核，数据仍有环境噪声。
