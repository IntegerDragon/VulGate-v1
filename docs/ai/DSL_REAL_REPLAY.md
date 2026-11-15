# DSL 真实应用重放记录（qizhi-51）

日期：2026-11-16  
环境：qizhi-51，Ubuntu 24.04，Python 3.12 venv，Frida 17.26.2。

## 目标

用 `runtime/dsl` 编译的补丁安装到真实应用进程，重放请求/操作，比较安装前后行为。
本记录只覆盖已实际跑通的 nginx 部分；其余用例列出阻塞原因。

## 已完成

### 真实 nginx 1.31.6 + CVE-2026-27654

- 二进制：`build/benchmark20/nginx-1.31.6/nginx`（从本地仓库拷贝到服务器 `/tmp/nginx-1.31.6`）
- 配置：`/tmp/ngx-replay/nginx.conf`，启用 `dav_methods`；
- 补丁：`runtime/dsl/patches/CVE-2026-27654.vg`，由于 `ngx_http_dav_copy_move_handler`
  是**本地符号**，使用 `runtime/frida/symbols.py` 计算 offset 后以
  `位置: symbol="...", offset=0x1194c1` 安装；
- 重放：

```
baseline COPY /dav/source.txt -> 204
安装 DSL 后 COPY /dav/source.txt -> 405
DSL hits = 1
```

结论：**该补丁在真实 nginx 上正确挂载并按动作返回 405。**

### 真实 nginx 1.31.6 + CVE-2026-42533

- offset 安装成功，`ngx_http_map_variable` 命中 1 次；
- 但 `/map/ordinary` 响应从 `200 "mapped"` 变为 `200 空`，未观察到明确错误状态；
- 需要进一步确认 nginx 对 `ngx_http_map_variable` 返回值的处理路径，暂不算通过。

### 真实 nginx 1.31.6 + CVE-2026-93479

- 安装成功，`ngx_http_script_check_length` 命中 222064 次；
- 响应仍为 200，原因：该 action 需要写 `ngx_http_script_engine_t.ip/status`
  （动作 writes），当前 DSL 编译器未实现 action writes。

## 未完成 / 阻塞

1. **真实 PoC 不在仓库中**：原仓库只有 `build/benchmark20` 的普通功能请求语料
   （`experiments/postdeploy/benchmark20/suite.py`），没有 20 个真实 exploit PoC。
2. **多数应用符号是本地符号**：DSL 已支持 `offset`，但每个 app build 需要生成
   offset 表；20 个 DSL 文件当前只写 symbol。
3. **action writes 未实现**：影响 93479、42945、9256（写 engine 字段）。
4. **PHP/Brotli**：服务器没有对应真实二进制/配置；需先构建或拷贝。
5. **httpd 需模块**：`httpd` 二进制需要 `mod_*.so` 与 APR 环境；且 httpd 多线程，
   当前 DSL 的 Frida NativeCallback 只适合单线程（可改 `ThreadsPerChild 1` 再测）。
6. 现有 20 例 DSL 的“验证”是合成 fixture + selector 注入，不是真实应用；
   本记录是真实应用重放的第一步。

## 下一步

1. 为每个 app build 生成 offset 表，批量把 20 个 DSL 的 `位置` 补成 module+offset；
2. 实现 action writes（engine 字段/动作副作用）；
3. 构建/拷贝 nginx/httpd/PHP/Brotli 真实目标，写 replay harness：
   - 启动应用 → Frida 安装 DSL → 发请求/操作 → 比较 baseline/patched；
4. 对条件补丁构造触发请求（alias/uri_changed、regex captures、blocked 阈值等）。
