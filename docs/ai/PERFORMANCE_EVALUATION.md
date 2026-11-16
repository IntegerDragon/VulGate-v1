# DSL→VM 性能评估方法

目标不是只测“平均耗时”，而是把 **安装开销**、**每次命中开销**、**应用吞吐/尾延迟** 和
**正确性代价** 分开测量，避免把 Frida 注入成本、VM 执行成本和业务流量混在一起。

## 1. 指标分层

### A. 安装/控制面

| 指标 | 单位 | 说明 |
|---|---|---|
| `resolve_ms` | ms | `/proc/<pid>/maps` + `nm` + DWARF + callsite 解析 |
| `compile_ms` | ms | DSL → eBPF 子集字节码 |
| `attach_ms` | ms | Frida attach、`Interceptor.replace/attach` |
| `agent_load_ms` | ms | bridge/agent 脚本加载 |
| `install_total_ms` | ms | 端到端安装时间 |
| `target_pause_ms` | ms | 目标在安装期间不可服务的时间 |
| `uninstall_ms` | ms | detach/恢复时间 |
| `rss_delta_kb` | KB | 目标进程安装前后 RSS |
| `map_bytes` | bytes | 程序级 map 池占用 |

安装开销只测一次，必须与稳态开销分开报告。

### B. 单次命中数据面

| 指标 | 单位 | 说明 |
|---|---|---|
| `hook_ns` | ns | Frida trampoline + 回调进入/退出 |
| `vm_ns` | ns | `vg_run` 执行 VM 的时间 |
| `helper_ns` | ns | `safe_read` / `map_get/set` 等 helper |
| `action_ns` | ns | BLOCK 动作构造返回值 |
| `hit_total_ns` | ns | 单次命中的总增量 |
| `vm_steps` | 条 | 本次执行的 VM 指令数 |
| `helper_calls` | 次 | 本次执行 helper 调用次数 |
| `step_limit_hits` | 次 | 触达 4096 步上限的次数 |
| `pass_hits/block_hits` | 次 | PASS/BLOCK 次数 |

### C. 应用级

| 指标 | 单位 | 说明 |
|---|---|---|
| `rps` | req/s | 吞吐 |
| `latency_p50/p95/p99` | ms | 请求延迟 |
| `latency_max` | ms | 最坏延迟 |
| `cpu_user/sys` | % | 目标进程 CPU |
| `instructions/request` | 条 | `perf stat` |
| `cycles/request` | cycles | `perf stat` |
| `cache_misses/request` | 次 | `perf stat` |
| `branch_misses/request` | 次 | `perf stat` |
| `rss_delta_kb` | KB | 稳态内存增量 |
| `block_rate` | % | 被拦截请求比例 |
| `false_positive/negative` | 次 | 差分语料统计 |

### D. 并发/正确性

- 线程数 1 / 4 / 8 下的 `rps`、`latency_p99`、`hit_total_ns` 分布；
- 多线程 map 竞争（当前 map 是程序级全局）；
- 安装/卸载期间服务可用性；
- 差分重放：PoC 必须被拦，正常流量必须放行；
- 崩溃/超时/连接关闭次数。

## 2. 测量方法

### 2.1 微基准（隔离 VM 成本）

C fixture：

```c
volatile uint64_t body_calls;
void target(uint64_t x) { body_calls++; }
int main(void) {
    // 循环 N=1e6 调用 target
}
```

对比四条路径：

1. 无 Frida；
2. 空 `Interceptor.attach`（只计 hook 成本）；
3. VM guard（不读内存、不写 map）；
4. VM guard + `safe_read`；
5. VM observer + map set / map get；
6. JS 后端回调（对照）。

用 `clock_gettime(CLOCK_MONOTONIC)` 在 fixture 内包住循环：

```text
ns_per_call = (end - start) / N
```

同时记录：

```text
hit_total_ns = (patched_time - baseline_time) / hits
```

### 2.2 桥接层计数器

在 `runtime/frida/bridge.c` 增加可选统计：

```c
typedef struct {
    uint64_t hits;
    uint64_t total_ns;
    uint64_t min_ns;
    uint64_t max_ns;
    uint64_t vm_steps_total;
    uint64_t helper_calls_total;
    uint64_t step_limit_hits;
} vg_stats;
```

在 `vg_run_with_maps` 前后用：

```c
clock_gettime(CLOCK_MONOTONIC, &start);
...
clock_gettime(CLOCK_MONOTONIC, &end);
```

注意：计时本身有开销；用于定位瓶颈，不要和关闭计时的生产数据混在一起。

### 2.3 真实应用

以 nginx 为例：

```sh
wrk -t4 -c100 -d60 --latency http://127.0.0.1:18080/...
```

固定：

- 同一 nginx 二进制、配置、worker 数；
- 同一请求/响应大小；
- 预热 10s；
- 每组重复 5 次，取中位数和 p95/p99；
- CPU 频率/核绑定记录；
- 分别测：无 patch、`--backend vm`、`--backend js`。

同时用：

```sh
perf stat -e cycles,instructions,cache-misses,branch-misses \
    -p <nginx-worker-pid> -- sleep 30
```

或对一轮请求运行 `perf stat`。

### 2.4 安装/在线开销

单独测量：

```text
t0 = 进入安装
t1 = resolve/compile 完成
t2 = Frida attach 完成
t3 = 第一条 hook 生效
```

并测量安装期间：

- 请求失败数；
- 最大停顿；
- 目标 RSS 增量。

### 2.5 正确性差分

同一组请求分别跑：

- baseline；
- patched VM。

统计：

```text
TP = PoC 被拦截
FN = PoC 放行
FP = 正常请求被拦截
TN = 正常请求放行
```

精度指标：

```text
recall = TP / (TP + FN)          # 拦截充分性
false_positive_rate = FP / (FP + TN)
```

这决定“细粒度”是否真的有效，不能只看性能。

## 3. 实验矩阵

| 维度 | 取值 |
|---|---|
| 后端 | 无 patch / VM / JS / native |
| patch 复杂度 | 无条件 / 单内存读 / 多次读 / map get / map set / observer |
| 挂载方式 | `Interceptor.replace` / `Interceptor.attach` |
| 负载 | 低并发 / 高并发 / 尾延迟 |
| 线程 | 1 / 4 / 8 |
| 安装阶段 | 安装中 / 稳态 / 卸载 |

## 4. 报告模板

```text
环境: CPU/内存/内核/Frida/nginx 版本
负载: wrk -t4 -c100 -d60，请求类型，预热
基线: rps, p50/p95/p99, CPU, instructions/request
VM:   rps, p50/p95/p99, CPU, instructions/request
JS:   同上
安装: resolve/compile/attach/total ms, 停顿 ms
命中: hits, pass/block, ns/hit p50/p95/p99, vm_steps/hit
正确性: TP/FN/FP/TN, recall, FPR
结论: 开销主要来自 hook / VM / helper 中哪一层
```

## 5. 预期瓶颈

1. **Frida hook/trampoline** 往往大于 VM 本身；
2. `safe_read` 的跨进程内存访问是主要 VM 成本；
3. map 全局锁/线性查找在容量大时退化；
4. observer 的 `Interceptor.attach` 比 guard 的 `replace` 更轻；
5. 多线程下 map 竞争和 Frida 回调安全限制；
6. 安装期 DWARF/反汇编只影响 control plane，不影响稳态。

因此至少报告：

```text
hook_ns vs vm_ns vs helper_ns
```

否则无法判断 DSL→VM 本身是否值得。
