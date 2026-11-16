# VulGate-v1：DSL 补丁 → Shadow VM → 用户态挂载

本仓库的核心链路：

```text
DSL 补丁
  ↓ 解析
PatchSpec（mount / action）
  ↓ 编译
VulGate Shadow VM 字节码（runtime/vm.c）
  ↓ 自动补 offset / 解析全局符号
Frida bridge（vulgate_frida.so）
  ↓ attach / spawn
Interceptor.replace(target, VM guard)
  ↓
VM 返回 PASS/BLOCK；BLOCK 执行动作，PASS 调原函数
```

目标：**输入一个 DSL 补丁，编译成 eBPF 风格字节码，自动解析本地符号，安装到运行中的用户态进程并验证。**

---

## 1. DSL 格式

英文关键字（中文别名兼容）：

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

条件补丁示例：

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
        value["len"] = vg_read_u32(arg0 + 8);
        if (value["len"] > 1024) {
            return block("REJECT");
        }
    }
}
```

字段：

| 字段 | 含义 |
|---|---|
| `action <id>` | BLOCK 动作 |
| `return_type` / `return` | 动作返回类型/值 |
| `errno` | 可选 |
| `mount <id>` | 挂载点 |
| `location` | `symbol`/`offset`，以及 `callsite(...)`、`line(...)`、`address(...)` |
| `nature` | `intercept` / `read_point` |
| `behavior` | C 风格行为代码 |

支持：

- `value["x"] = <expr>;` 观察槽位；
- `argN`、`global("符号")`；
- `vg_read_u8/u16/u32/u64/pointer`；
- `if`、比较/算术/位运算、`&& || !`；
- `return block("ACTION");`；不写 return 则 PASS。

---

## 2. 编译设计

### 2.1 解析（`runtime/dsl/parser.py`）

- 提取 `action` / `mount` 顶层块；
- 解析 `location` 与嵌套 `behavior`；
- 输出 `PatchSpec`。

### 2.2 DSL → VM 字节码（`runtime/dsl/vm.py`）

不是 JS 回调；每个 mount 编译成 `runtime/vm.c` 能执行的 eBPF 子集程序：

```text
值表达式 → VM 寄存器/helper
  argN            → get_arg
  global("x")     → 安装期解析成绝对地址常量
  vg_read_u32(p)  → safe_read_u32
  算术/位运算     → ALU 指令

条件 → 跳转
  == != < <= > >= / && / || / ! → 条件分支
  block 标签：r0=1; exit
  pass  标签：r0=0; exit
```

VM 返回 `SHADOW_PASS(0)` / `SHADOW_BLOCK(1)`，动作由安装器在 BLOCK 时执行。

### 2.3 程序级 map + 观察点

DSL 支持声明程序级 map：

```text
map limits:
{
    capacity: 16
}
```

观察点（`nature: read_point`）编译成 observer VM 程序，通过 `Interceptor.attach`
安装；它只写 map、继续执行原函数：

```text
mount observe_limit:
{
    location: symbol="observe_limit", args=[uint64, uint64], return=void
    nature: read_point
    behavior:
    {
        map["limits"]["max_upload"] = arg1;
    }
}
```

拦截点读取同一 map：

```text
value["limit"] = map["limits"]["max_upload"];
if (arg1 > value["limit"]) {
    return block("REJECT");
}
```

实现：

- map 由安装器创建为程序级对象（`vg_map_pool_create`），所有 observer/guard 共享；
- observer/guard 都通过 `vg_run_with_maps` 执行 VM；
- map helper：`MAP_SET` / `MAP_GET` / `MAP_PRESENT` / `MAP_DELETE`；
- 字符串 key 在编译期映射为 per-map 的 `u64` key id；也支持动态 u64 key：

```text
map["current_input"][arg0] = arg1;
value["available_in"] = map_take("current_input", arg0);
value["present"] = map_present("current_input", arg0);
```

- `map_take` = 读取后删除（consume）；`map_present` = 只判断 key 是否存在；
- `local("available_in")` 从 caller 局部变量读取：

```text
map["current_input"][arg0] = local("available_in");
```

- 局部变量通过 DWARF `DW_AT_location`（`DW_OP_fbreg` / `DW_OP_reg` / `DW_OP_breg`）
  在安装时解析，callsite 触发时从 Frida 寄存器/栈读取；
- 支持 callsite/line 位置解析，不需要显式 offset。

当前编译支持 20 个快速拦截补丁所需的子集；不支持：
- 有界循环/任意临时变量（可后续加 lowering）；
- action writes；
- 调用点/callsite observer（只支持函数入口观察点）。

### 2.4 位置解析（x86-64）

DSL 不需要显式写 offset，可以直接描述位置：

```text
location: callsite(caller="BrotliDecoderDecompressStream",
                   callee="WriteRingBuffer", line=2426)

location: line(file="decode.c", line=2426)

location: address(module="libpd_brotli.so", offset=0x1234)
```

解析流程（`runtime/dsl/x86.py`）：

1. 用 `nm -S` 得到 caller/callee 的符号地址与函数范围；
2. `objdump -d` 反汇编 caller，找 `call callee` 指令；
3. 若给 `line/file`，用 `addr2line` 过滤；
4. 用 DWARF decoded line 支持 `line(file,line)`；
5. 输出 module-relative offset，安装时 `module.base + offset`。

callsite observer 验证：

```text
location: callsite(caller="caller", callee="callee")
```

用户态 fixture 结果：

```text
callsite offset 0x11fb, target 0x4011fb
guard target 0x4011b6
result body_calls=0（callsite observer 写入 map，callee 被 BLOCK）
```

当前只适配 **x86-64 Linux**；PLT/内联调用解析有限。

### 2.5 自动补 offset

`runtime/dsl/resolve.py`：

1. 读 `/proc/<pid>/maps` 找模块路径与 load base；
2. `runtime/frida/symbols.py` 从 `nm` 计算 `symbol_offset`；
3. 绝对地址 = module base + offset；
4. 对 `--spawn`：Frida 先挂起目标，maps 可用后再编译/安装；
5. `global("x")` 同样解析成绝对地址常量。

### 2.6 安装（`runtime/dsl/vm_run.py`）

- 编译 bridge：`vulgate_frida.so`（含 `runtime/vm.c`）；
- 为每个 mount：
  - `vg_program_create(bytecode)`；
  - `SystemFunction` 保存原函数；
  - `NativeCallback` 打包参数，`vg_run` 执行 VM；
  - BLOCK 返回动作值，PASS 调原函数；
  - `Interceptor.replace`；
- 输出挂载点、目标地址、命中计数。

---

## 3. 用法

### 3.1 检查 DSL / 显示 mounts

```sh
python -m runtime.dsl.run --dsl patch.vg --check
```

### 3.2 安装到运行中进程（默认走 VM）

```sh
python -m runtime.dsl.run --dsl patch.vg --pid 1234 --duration 30
```

### 3.3 spawn 并安装

```sh
python -m runtime.dsl.run --dsl patch.vg --spawn ./target --duration 30
```

### 3.4 显式指定 VM bridge

```sh
python -m runtime.dsl.run --dsl patch.vg --pid 1234 \
    --bridge-dir build/frida-vm
```

### 3.5 保留 JS 后端（对照用）

```sh
python -m runtime.dsl.run --dsl patch.vg --pid 1234 --backend js
```

JS 后端现在只作为对照/应急路径；默认是 VM。

---

## 4. 20 个 CVE 补丁

`runtime/dsl/patches/*.vg`：

- 17 个 action 无 writes，天然 return-only；
- 3 个写依赖补丁改成 return-only 挂载：
  - `CVE-2026-93479` 恢复到官方粒度 `ngx_http_script_check_length + length != 0`，返回 -1；
  另提供更细的 `patches_fine/CVE-2026-93479.vg`（`end - pos < len`）；
  - `CVE-2026-42945` / `9256` → `ngx_http_rewrite_handler` 返回 500；
- `CVE-2026-111497` 已恢复原始 observer 语义：callsite observer + `local("available_in")`
  + 动态 key `arg0` + `map_present` / `map_take`；用合成 brotli fixture 单独验证；
- 分析见 `docs/ai/DSL_RETURN_ONLY_ANALYSIS.md`。

### 合成 fixture VM 验证

```sh
python -m runtime.dsl.vm_validate
```

最近结果：**24/24 VM 场景通过**（111497 / 93479 单独验证）。

### 程序级 map / observer / callsite / local 验证

```sh
python -m runtime.dsl.vm_map_validate
python -m runtime.dsl.vm_callsite_validate
python -m runtime.dsl.vm_brotli_validate
python -m runtime.dsl.vm_php_validate
python -m runtime.dsl.vm_93479_validate
```

- `vm_map_validate`：动态 key + `map_take` consume；
  - 第一次 `target_fn(1,101)` → BLOCK（-73）；
  - 第二次 `target_fn(1,101)` → PASS（0，key 已消费）；
  - `body_calls=1`。
- `vm_callsite_validate`：callsite observer + `local("available_in")`，`body_calls=0`。
- `vm_brotli_validate`：原始 111497 DSL（callsite + local + 动态 key +
  `map_present` / `map_take`），`body_calls=0`。
- `vm_php_validate`：PHP 109618 原 DSL 的全局 selector 真实读取，`body_calls=0`；
- `vm_93479_validate`：官方粒度 `check_length + length != 0` 和细粒度 `end - pos < len` 两个版本。

### 真实 nginx 1.31.6 验证

| 用例 | 请求 | baseline | VM patched |
|---|---|---|---|
| CVE-2026-27654 | DAV `COPY` | 204 | **405** |
| CVE-2026-93479（官方粒度） | `/dynamic/file.txt?dir=www` | 200 | 200（已命中，无 writes 不产生 500） |
| CVE-2026-42945 | `/rewrite/ordinary` | 302 | **500** |

均通过 `runtime.dsl.vm_run` 安装，命中计数为 1。

---

## 5. 仓库结构

```text
runtime/dsl/        DSL 解析、VM 字节码编译、自动 offset、VM 安装、20 个补丁
runtime/vm.c        Shadow VM（eBPF 子集、只读判定）
runtime/frida/      Frida bridge/agent、多进程、metrics/控制通道
runtime/native/     plthook / inline 原生后端（实验）
runtime/preload/    LD_PRELOAD 原生模式
tests/              DSL VM/JS、Frida、native、baseline 测试
docs/ai/            设计、限制、真实重放记录
deploy/             systemd/权限说明
```

---

## 6. 当前限制

- VM 只读，不支持 action writes（写字段需后续两阶段 action）；
- DSL → VM 目前只支持 20 例子集：无循环、callsite 仅解析直接 call（PLT/内联有限）；
- 位置解析只适配 x86-64 Linux；
- map 支持编译期字面量 key 和动态 u64 key；运行时字符串 key 还未支持；
- map 仍是程序级全局，没有 thread-scoped 分片；
- caller 局部变量只支持 DWARF exprloc（reg/breg/fbreg/const/deref）；loclist 尚未实现；
- Frida 回调仍只适合单线程路径；
- 没有常驻 daemon / uninstall 子命令；
- 安装失败无完整事务回滚；
- 真实应用只验证了 nginx 的 3 条路径；httpd/PHP/Brotli 未真实重放；
- 自动 offset 依赖可读 ELF 和 `nm`；stripped 目标仍需手工 offset。
