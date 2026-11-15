# Return-only 可达性分析（20 个 DSL 补丁）

日期：2026-11-16  
目标：对需要 action writes 的补丁，判断能否改挂到“返回值被调用者检查”的非 void 函数，
用纯 return 实现 BLOCK；不能转换的从交付集中去掉。

## 结论

- 17/20 的 action 本来就没有 `writes`，已经是 return-only；
- 3/20 需要 action writes：`CVE-2026-93479`、`CVE-2026-42945`、`CVE-2026-9256`；
- 这 3 个都找到了可用的 return-only 挂载点，**无需删除任何漏洞**；
- 代价是挂载范围比原补丁更宽（语义漂移），需在文档中标注。

## 三个写依赖补丁的转换

| CVE | 原挂载 | 原动作 writes | return-only 挂载 | 返回 | 真实 nginx 实测 |
|---|---|---|---|---|---|
| CVE-2026-93479 | `ngx_http_script_check_length` | `engine->ip`、`engine->status=500` | `ngx_http_script_run` | `NULL` | baseline 200 → patched **500**，hit 1 |
| CVE-2026-42945 | `ngx_http_script_regex_start_code`（void） | `engine->ip`、`engine->status=500` | `ngx_http_rewrite_handler` | `500` | baseline 302 → patched **500**，hit 1 |
| CVE-2026-9256 | 同上（void） | 同上 | `ngx_http_rewrite_handler` | `500` | 与 42945 共用模板；同函数同动作 |

转换后的 DSL 位于：

- `runtime/dsl/patches/CVE-2026-93479.vg`
- `runtime/dsl/patches/CVE-2026-42945.vg`
- `runtime/dsl/patches/CVE-2026-9256.vg`

## 其余 17 个

这些 action 只有返回值/errno，没有 writes，本来就是 return-only：

```
109618, 109619, 111497, 15176, 27654, 42055(x2), 42533, 47360,
56153, 56154, 56449, 57941, 60005, 63292, 63686, 93546, 97205
```

注意：return-only 只保证“补丁动作可以被表达”，不代表每个都在真实应用上产生了预期 HTTP 效果；
例如 `42533` 返回 -1 后真实响应是 200 空，没有明确错误状态，需要单独做路径语义验证。

## 转换判据

一个写依赖补丁可以改成 return-only，当且仅当：

1. 调用链上存在非 void 函数；
2. 该函数的返回值被调用者检查并用于中止/错误传播；
3. 阻塞范围扩大可接受；
4. 调用者不会读取未初始化/旧状态导致崩溃。

`CVE-2026-42945/9256` 原目标是 `void`，不能在原挂载点 return-only；改用
`ngx_http_rewrite_handler`（返回 `ngx_int_t`，返回 500 会让 nginx 直接结束请求）。

## 验证

服务器 `qizhi-51`：

- 合成 fixture：**28/28 场景通过**（20 BLOCK + 6 PASS + 2 memory）；
- 真实 nginx 1.31.6：
  - `CVE-2026-93479`：`/dynamic/file.txt?dir=www` 200 → 500，hit 1；
  - `CVE-2026-42945`：`/rewrite/ordinary` 302 → 500，hit 1；
- `CVE-2026-27654`：此前已实测 DAV COPY 204 → 405。

## 已知限制

- return-only 版本改变了挂载点，可能拦截比原漏洞更大的范围；
- 条件补丁的 selector 逻辑被替换为无条件拦截（93479/42945/9256 的转换版本都是 `if (true)`）；
- 真实应用覆盖仍只验证了 nginx 的 3 个请求路径；httpd/PHP/Brotli 未做真实重放。
