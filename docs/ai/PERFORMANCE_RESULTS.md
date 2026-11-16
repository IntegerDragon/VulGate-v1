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
