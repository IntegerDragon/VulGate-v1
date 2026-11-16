# DSL→VM 实测结果（20 个补丁）

## 环境

```text
host: qizhi-51 (Linux x86-64)
injector: Frida 17.26.2 + Python 3.12
fixture: gcc -O0 -g -rdynamic
loop: 100,000 次/进程；取 3 次中位数
VM-only: 1,000,000 次/进程
```

## 测量口径

1. **VM-only**：C harness 直接执行编译后的 VM 字节码，
   不含 Frida、JS 回调、参数打包；
2. **full chain**：Frida `Interceptor.replace` → JS `NativeCallback`
   → `vg_run_with_maps` → VM → action，即当前实际用户态链路；
3. baseline：同一 fixture 不安装补丁，执行同样的函数调用循环；
4. full-chain 的 BLOCK 路径不执行原函数体，因此
   `overhead` 是“拦截开销”的上界（原函数体本身只有一次计数器自增）。

## 结果

| CVE | mounts | VM 字节码 (bytes) | VM-only (ns/run) | full chain (ns/hit) | baseline (ns/call) | install (ms) |
|---|---:|---:|---:|---:|---:|---:|
| 109618 | 1 | 128 | 86.08 | 6180.89 | 9.07 | 128.62 |
| 109619 | 1 | 40 | 62.81 | 7482.14 | 7.66 | 131.17 |
| 111497 | 2 | 168* | N/A（observer+map） | 16964.95 | 12.89 | 110.19 |
| 15176 | 1 | 112 | 79.27 | 8608.29 | 7.65 | 95.42 |
| 27654 | 1 | 40 | 62.98 | 4848.95 | 9.11 | 100.11 |
| 42055 | 2 | 40 | 61.87 | 4812.98 | 9.21 | 96.62 |
| 42533 | 1 | 40 | 62.80 | 7507.81 | 8.88 | 101.31 |
| 42945 | 1 | 40 | 64.12 | 4904.64 | 7.93 | 103.62 |
| 47360 | 1 | 64 | 64.34 | 4892.68 | 7.70 | 103.34 |
| 56153 | 1 | 40 | 61.60 | 6099.81 | 9.24 | 95.67 |
| 56154 | 1 | 40 | 62.21 | 6167.07 | 7.53 | 94.17 |
| 56449 | 1 | 40 | 65.21 | 6096.34 | 8.41 | 96.45 |
| 57941 | 1 | 40 | 61.24 | 7563.65 | 7.59 | 117.82 |
| 60005 | 1 | 112 | 81.02 | 7588.11 | 7.64 | 118.31 |
| 63292 | 1 | 40 | 62.96 | 4959.58 | 8.41 | 113.04 |
| 63686 | 1 | 40 | 62.37 | 6126.34 | 9.35 | 119.34 |
| 9256 | 1 | 40 | 65.06 | 4962.27 | 7.75 | 116.94 |
| 93479 | 1 | 80 | 72.12 | 6305.08 | 8.75 | 117.15 |
| 93546 | 1 | 40 | 62.51 | 4967.05 | 9.00 | 116.97 |
| 97205 | 1 | 96 | 76.77 | 6267.63 | 8.91 | 119.56 |

\*111497 为两个 VM 程序（observer 64 + guard 104 bytes），VM-only 未单独测 map 池。

## 结论

1. **VM 本身很便宜**：19 个可单测补丁在 **61–86 ns/run**；
2. **full chain 约 4.8–8.6 µs/hit**；
3. 因此当前链路的主要成本是：
   ```text
   Frida hook/trampoline
   + JS NativeCallback
   + 参数/上下文打包
   + NativeFunction 调用
   ```
   而不是 VM 解释器；
4. 111497 有两个 hook（callsite observer + guard），约 **17 µs/call**，
   与“单 hook 约 8 µs”一致；
5. 安装时间约 **95–131 ms**，属于 control plane，不影响稳态单次命中。

粗略占比：

```text
VM-only:        ~1–2%
Frida + JS + marshal: ~98–99%
```

所以后续性能优化优先级应是：

1. 减少 Frida/JS 回调与 marshalling；
2. 减少 hook 数量（observer+guard 合并或 native backend）；
3. 最后才是 VM 指令/helper 优化。

## 未测量

- 真实 nginx 的 RPS / p50/p95/p99（本表是合成 fixture 微基准）；
- `perf stat` 的 instructions/cache/branch misses；
- 多线程/并发 map 竞争；
- JS backend 对照；
- native plthook/inline backend 对照。

这些按 `docs/ai/PERFORMANCE_EVALUATION.md` 的方法补测。

---

## 六、真实 nginx 应用级

目标：`nginx 1.31.6`，单进程（`master_process off`），
请求 `/rewrite/ordinary`，补丁 `CVE-2026-42945`（rewrite_handler 无条件 500）。

负载：本地 `http.client` 32 线程闭路，10 s，预热 1 s。

| 模式 | RPS | p50 ms | p95 ms | p99 ms | 状态 |
|---|---:|---:|---:|---:|---|
| baseline | 894.52 | 30.015 | 76.158 | 101.697 | 302 |
| VM backend | 859.97 | 33.087 | 79.776 | 106.807 | 500 |
| JS backend | 856.49 | 32.994 | 80.834 | 105.053 | 500 |

重复两次的范围：

```text
baseline RPS: 894.52–939.59
VM RPS:       843.11–859.97
JS RPS:       841.92–856.49

baseline p95: 73.30–76.16 ms
VM p95:       79.78–80.81 ms
JS p95:       80.83–80.99 ms
```

解读：

- 该补丁改变了响应（302→500），所以 RPS 差异包含业务路径差异；
- VM 与 JS backend 几乎相同，说明当前瓶颈在 Frida/JS 回调，不在 VM；
- 相对 baseline，VM/JS 的 p95 增加约 3.6–4.7 ms，主要是每请求多一次
  Frida→JS→VM 链，以及 302/500 路径差异。

`perf stat`（同一次 10 s 负载，block 路径）：

| 模式 | cycles | instructions | cache-misses | branch-misses | 请求数 |
|---|---:|---:|---:|---:|---:|
| baseline | 15.94 B | 62.83 B | 0.624 M | 10.96 M | 9397 |
| VM | 5.47 B | 18.08 B | 1.897 M | 14.79 M | 8652 |

注意：VM 模式走 500 提前返回，指令数明显更少，**不能直接用这组数算 overhead**。
它只能说明 500 路径本身的指令数更低，以及 branch-misses/request 更高。

## 七、Pass-through 对照（失败）

为了在“相同业务路径”下测链开销，构造了一个恒 PASS 的 rewrite 补丁：

```text
mount pass_rewrite:
    if (false) return block(...)
```

结果：

```text
baseline: 903.83 RPS, 302
VM:       0 RPS, 96 errors，请求超时
JS:       0 RPS, 96 errors，请求超时
```

detach 后 nginx 恢复，说明不是进程崩溃，而是 **PASS 回调在 nginx 上挂住**。
合成 fixture 的 PASS 路径可以完成（例如 93479 len=0 场景），但真实 nginx
的 PASS 链路当前不可用/不稳定。

这也是为什么上表只能用 BLOCK 路径做应用级测量。

## 八、多线程

用 pthread fixture（1/4 个线程，每线程 20k 次调用）测 Frida→VM 链：

```text
threads=1: no fixture result（挂住）
threads=4: no fixture result（挂住）
```

在合成单线程 fixture 上同样的 patch 可以完成；多线程回调当前会挂住，
和之前“Frida 回调只适合单线程路径”的限制一致。

因此：

- **多线程并发 map 竞争没有可报告数据**；
- 当前实现不能用于多线程目标；
- 必须先做 thread-scoped map + Frida 回调线程安全，才能测并发。

## 九、Native / PHP / httpd / brotli

服务器检查结果：

- `build/native` 不存在，native plthook/inline 未构建；
- `php`、`httpd` 命令不存在；
- 系统有 `libbrotli*.so`，但没有 patch 目标 `libpd_brotli.so`，
  且 `WriteRingBuffer` 是内部符号，不能直接替换。

因此：

| 项目 | 状态 |
|---|---|
| native backend 对照 | 未测（未构建） |
| 真实 PHP | 未测（无目标） |
| 真实 httpd | 未测（无目标） |
| 真实 brotli | 未测（无目标） |
| 真实 nginx | 已测（上表） |

## 十、目前能下的性能结论

1. 合成链：VM 61–86 ns，完整 Frida→VM 4.8–8.6 µs/hit；
2. 真实 nginx：RPS 约 -4%，p95 +3.6–4.7 ms（含 302/500 路径差异）；
3. VM 与 JS backend 几乎同速 → 瓶颈在 Frida/JS/marshal；
4. PASS 路径在 nginx 上挂住，当前只能可靠测 BLOCK 路径；
5. 多线程会挂住，当前不可用；
6. native/PHP/httpd/brotli 目标缺失，无法实测。
