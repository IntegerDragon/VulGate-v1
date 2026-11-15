# VulGate-v1：从补丁 DSL 到热挂载

本仓库的核心链路是：

```text
DSL 补丁文件
   ↓ 解析
PatchSpec（mount / action）
   ↓ 编译
Frida agent（NativeCallback + SystemFunction）
   ↓ 注入
attach / spawn 目标进程
   ↓
Interceptor.replace(target, guard)
   ↓
运行：VM/行为判定 → BLOCK 执行动作，或 PASS 调用原函数
```

目标：**输入一个 DSL 补丁，自动解析、编译、安装到运行中的用户态进程，并验证是否生效。**

---

## 1. DSL 格式

英文关键字（中文别名仍兼容）：

```text
action NGX_HTTP_405_RETURN:
{
    return_type: int
    return: 405
}

mount CVE-2026-27654/ngx_http_dav_copy_move_handler:
{
    location: symbol="ngx_http_dav_copy_move_handler", args=[pointer], return=int64
    nature: intercept
    behavior:
    {
        if (true) {
            return block("NGX_HTTP_405_RETURN");
        }
    }
}
```

### 字段

| 字段 | 含义 |
|---|---|
| `action <id>:` | BLOCK 动作 |
| `return_type` | 动作/函数返回类型：`int/int64/uint/uint64/pointer/void/float/double/string` |
| `return` | 动作返回值（`null`/整数/字符串） |
| `errno` | 可选，设置线程 errno |
| `mount <id>:` | 一个挂载点 |
| `location` | `module`（可选）、`symbol`、`offset`（可选）、`args`、`return` |
| `nature` | `intercept`（拦截点）或 `read_point`（读取点） |
| `behavior` | C 风格行为代码 |

### 行为代码

- `value["x"] = <表达式>;`：记录观察值/selector；
- `value["x"]`：读取观察值；
- `return block("ACTION");`：BLOCK；
- 不写 `return`：PASS，调用原函数；
- 支持 `if`、算术/比较/位运算、临时变量、有界 `for`；
- 内存读取辅助函数：
  `vg_read_u8/u16/u32/u64`、`vg_read_s8/...`、`vg_read_pointer`、`global("符号")`。

### 示例：条件拦截

```text
action REJECT:
{
    return_type: int
    return: -73
}

mount demo:
{
    location: symbol="target_fn", args=[pointer, uint64], return=int
    nature: intercept
    behavior:
    {
        value["length"] = vg_read_u32(arg0 + 8);
        if (value["length"] > 1024) {
            return block("REJECT");
        }
    }
}
```

---

## 2. 编译设计

### 2.1 解析（`runtime/dsl/parser.py`）

- 扫描顶层 `action` / `mount`；
- 按花括号配平提取 `behavior` 嵌套块；
- 解析 `location`：`module/symbol/offset/args/return`；
- 输出 `PatchSpec(actions, mounts)`。

### 2.2 编译（`runtime/dsl/compiler.py`）

每个 mount 生成一个 Frida agent 片段：

```text
SystemFunction(target, return_type, args)     # 原函数
NativeCallback(function(arg0, ...) {
    <编译后的 behavior>
    return original(...);                     # PASS
}, return_type, args)
Interceptor.replace(target, callback)
```

行为转换：

| DSL | 编译结果 |
|---|---|
| `value["x"] = <expr>;` | `value["x"] = vg_sel("x", () => (<expr>));` |
| `return block("ID");` | `return vg_block("ID");` |
| `int x = ...;` | `let x = ...;` |
| `True/False` | `true/false` |
| `read_* / global` | JS 辅助函数，走 `Memory.read*` / `Module.getExportByName` |

动作侧：

- 动作表编译为 JS 对象；
- `vg_block` 按返回类型生成返回值（整数/指针/null/字符串）；
- 可选 errno；
- 每个 mount 有命中计数，`status()` 可查。

### 2.3 自动补 offset

真实应用的很多函数**不是动态导出符号**（nginx/httpd 尤其多）。只写 `symbol` 时：

1. 读取目标进程 `/proc/<pid>/maps`，得到主程序与共享库路径；
2. 根据 `location.module`（或默认主程序）选择 ELF；
3. 用 `runtime/frida/symbols.py` 从 `nm` 符号表计算模块相对 offset；
4. 写回 `mount.offset`，编译时生成 `module.base + offset` 解析；
5. 仍是动态导出符号时，也可以继续走 `getExportByName`。

相关代码：`runtime/dsl/resolve.py`。

对于 `--spawn`，目标先被 Frida 挂起，`/proc/<pid>/maps` 已建立，再解析 offset、编译、安装，最后 resume。

可选覆盖：

```sh
python -m runtime.dsl.run --dsl patch.vg --spawn ./target \
    --module-binary mod_proxy.so=/path/to/mod_proxy.so
```

### 2.4 安装

`runtime/dsl/run.py`：

```sh
# 只解析/编译并显示自动 offset
python -m runtime.dsl.run --dsl patch.vg --pid 1234 --check

# 安装到运行中进程
python -m runtime.dsl.run --dsl patch.vg --pid 1234 --duration 30

# spawn + 挂起时解析 offset + 安装
python -m runtime.dsl.run --dsl patch.vg --spawn ./target --duration 30
```

输出包含：

- `mounts`：每个挂载点的 `symbol/module/offset/args/return`；
- `installed`：实际替换的目标地址；
- `hits`：每个 mount 的命中次数。

---

## 3. 用法

### 3.1 本地验证

```sh
python -m pytest tests/test_dsl.py tests/test_dsl_resolve.py -q
```

### 3.2 合成 fixture 验证（20 个 CVE）

```sh
python -m runtime.dsl.validate20 --json /tmp/dsl20.json
```

最近结果：**28/28 场景通过**（20 个 BLOCK + 6 个 PASS + 2 个 memory）。

### 3.3 真实应用验证

已实测 nginx 1.31.6：

| 用例 | 请求 | baseline | patched |
|---|---|---|---|
| CVE-2026-27654 | DAV `COPY` | 204 | **405** |
| CVE-2026-93479（return-only） | `/dynamic/file.txt?dir=www` | 200 | **500** |
| CVE-2026-42945（return-only） | `/rewrite/ordinary` | 302 | **500** |

自动 offset 已用于真实 nginx：

```sh
python -m runtime.dsl.run --pid <nginx-pid> \
    --dsl runtime/dsl/patches/CVE-2026-27654.vg --duration 6
```

日志中 `offset` 自动填充为 `0x1194c1`，COPY 从 204 变为 405。

### 3.4 20 个 CVE 补丁

`runtime/dsl/patches/*.vg` 共 20 个：

- 17 个 action 无 writes，天然 return-only；
- 3 个写依赖补丁已改成 return-only 挂载：
  - `CVE-2026-93479` → `ngx_http_script_run` 返回 NULL；
  - `CVE-2026-42945`/`9256` → `ngx_http_rewrite_handler` 返回 500。
- 分析见 `docs/ai/DSL_RETURN_ONLY_ANALYSIS.md`。

---

## 4. 仓库结构

```text
runtime/dsl/           DSL 解析、编译、自动 offset、安装、20 个补丁
runtime/frida/         Frida Python 注入器/多进程/指标/控制通道
runtime/native/        plthook / inline 原生后端（实验）
runtime/preload/       LD_PRELOAD 原生模式
runtime/vm.c           Shadow VM（只读判定）
experiments/           成熟 hook 库、native-frida 可行性实验
tests/                 DSL/ Frida / native / baseline 测试
docs/ai/               设计、限制、真实重放记录
deploy/                systemd 与权限说明
```

---

## 5. 当前限制

- **单线程路径**：DSL 编译为 Frida `NativeCallback`，只适用于主线程/串行调用；多线程需 native 后端；
- **action writes 未实现**：写结构体字段的动作尚不支持，已用 return-only 绕过；
- **没有常驻安装/uninstall 命令**：`run.py --duration` 结束后 detach，适合测试窗口；
- **安装失败无事务回滚**：多个 mount 时可能部分安装；
- **未自动多进程发现**：一次只处理一个 pid/spawn；
- 真实应用只验证了 nginx 的 3 个请求路径；httpd/PHP/Brotli 尚未真实重放；
- 20 个补丁的合成验证使用 selector 注入，不能替代真实请求重放。

---

## 6. 开发与测试环境

服务器（不再使用 WSL）：

- 主机：`qizhi-51`，代码：`/kyz/VulGate-v1`
- venv：`.venv`（frida 17.26.2 / pytest / pyelftools）
- 测试：

```sh
ssh qizhi-51 "cd /kyz/VulGate-v1 && \
  .venv/bin/python -m pytest tests/test_dsl.py tests/test_dsl_resolve.py -q"
```

本地修改可通过 `tools/sync_to_qizhi51.py` 快速同步；正式提交后服务器 `git pull --ff-only`。
