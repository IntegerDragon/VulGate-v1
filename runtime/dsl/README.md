# VulGate Patch DSL

`runtime/dsl/` 是补丁 DSL 的编译/解释层：把“挂载点 + 行为”的补丁描述编译成
Frida agent（`NativeCallback` + `SystemFunction`），在目标进程里安装并执行。

## DSL 语法（英文关键字）

```text
action NGX_ERROR_RETURN:
{
    return_type: int
    return: -1
}

mount CVE-2026-97205:
{
    location: symbol="ngx_http_copy_filter", args=[pointer, pointer], return=int64
    nature: intercept
    behavior:
    {
        value["counter"] = vg_read_u32(vg_read_pointer(arg0 + 1000) + 1181);
        if ((value["counter"] & 255) >= 250) {
            return block("NGX_ERROR_RETURN");
        }
    }
}
```

- `mount <id>:`：一个挂载点；
- `location`：`module`（可选）、`symbol`、`offset`（本地符号）、`args`、`return`；
- `nature`：`read_point` 或 `intercept`；
- `behavior`：C 风格语句。`value["x"] = ...` 写入观察值，后续可直接读 `value["x"]`；
  `return block("ACTION");` 表示 BLOCK；不写 return 则落到 PASS，调用原函数；
- `action <id>:`：BLOCK 返回动作；`return_type`/`return`/可选 `errno`。

旧的中文关键字（`动作/挂载点/位置/性质/行为/读取点/拦截点/参数/返回类型/返回`）仍被解析器接受，
但生成器和仓库内 20 个补丁统一使用英文。

## 编译实现

1. `parser.py`：扫描 `action`/`mount` 顶层块，按花括号配平提取 `behavior`；
   解析 `location` 的 `module/symbol/offset/args/return` 和动作字段；
2. `compiler.py` 把每个 mount 编译成一个 Frida agent 片段：
   - 每个 `value["x"] = <expr>` 变成 `value["x"] = vg_sel("x", () => (<expr>))`
     （生产模式执行真实内存读取；验证模式可注入 selector 值）；
   - `return block("ACTION")` 变成 `return vg_block("ACTION")`；
   - C 风格临时变量/`for` 声明转成 JS `let`；
   - 动作表编译为 JS 对象，`vg_block` 按返回类型生成返回值/`errno`；
   - 每个 mount 生成：
     - `new SystemFunction(target, return_type, args)` 保存原函数；
     - `new NativeCallback(function(arg0...) { ...; return original(...); }, ...)`；
     - `Interceptor.replace(target, callback)` 安装；
   - 支持 `offset`：`module.base.add(offset)` 解析本地符号；
3. `run.py`：Frida Python 读取 DSL → 自动补 offset → 编译 → attach/spawn → 安装；
   `resolve.py`：读 `/proc/<pid>/maps`，用 `nm` 符号表为本地符号自动计算
   `module.base + offset`；
   `validate20.py`：合成 fixture 验证 BLOCK/PASS/memory 场景。

## 编译/安装

```sh
# 只编译检查
python -m runtime.dsl.run --dsl runtime/dsl/patches/CVE-2026-97205.vg --check

# spawn 目标并安装
python -m runtime.dsl.run --dsl runtime/dsl/patches/CVE-2026-97205.vg \
    --spawn ./target --duration 5

# 已有进程
python -m runtime.dsl.run --dsl runtime/dsl/patches/CVE-2026-97205.vg \
    --pid 1234 --duration 5
```

## 20 个 CVE 的 DSL

`runtime/dsl/patches/*.vg` 由 `build/declarative20-specs` 的
`patch.yaml + app_profile` 生成：

```sh
python -m runtime.dsl.generate20 --out runtime/dsl/patches
```

生成器需要 `PyYAML`（`requirements-dsl.txt`）。

## 验证

```sh
python -m runtime.dsl.validate20 --json /tmp/dsl20.json
```

验证器为每个 DSL 生成一个小型 fixture 可执行文件（导出目标符号、统计函数体执行次数），
用 Frida 安装 DSL agent，然后调用目标：

- **BLOCK**：`body_calls == 0`，返回动作值；
- **PASS**：条件不成立时 `body_calls > 0`，返回原函数结果；
- **memory 模式**：不注入 selector 值，真实执行内存读取（当前对 `CVE-2026-93479` 跑通）。

服务器 qizhi-51 实测（2026-11-16）：

```
28/28 DSL scenarios passed (block + pass)
```

其中 20 个 CVE 全部 BLOCK 通过；6 个条件式补丁额外验证 PASS；
`CVE-2026-109618`（全局符号）、`CVE-2026-47360`（指针字段）额外以 memory 模式验证真实内存读取。
`CVE-2026-93479`/`42945`/`9256` 已改为 return-only 挂载（见
`docs/ai/DSL_RETURN_ONLY_ANALYSIS.md`）。

## 支持的表达式与动作

- 表达式：`== != < <= > >=`、`&& || !`、`+ - *`、`& | ^ << >>`、括号、常量；
- 内存读取：`vg_read_u8/u16/u32/u64`、`vg_read_s8/...`、`vg_read_pointer`；
- 全局符号：`global("name")`；
- 行为里可写临时变量（编译为 JS `let`）、`if`、有界 `for`；
- 动作：`return_int/int64/void/null/string/float/double`；`errno` 可选。

## 限制（当前版本）

- 生成的是 **Frida NativeCallback**，与 Frida 后端一样只适用于**单线程/主线程串行调用路径**；
- 结构体 by-value/sret 返回暂不支持；
- `vg_map_get`/`vg_map_present` 目前是占位实现（brotli 观察点的真实 callsite 语义未接入）；
- 动作的 `writes` 尚未在 DSL 编译器中执行；当前验证以返回值/函数体是否执行为准；
- 2 例以 memory 模式验证（`CVE-2026-109618`/`CVE-2026-47360`）；
  其余 18 例通过 `vg_sel` 注入 selector 值验证行为分支，编译产物中的内存读取代码未在真实应用上执行；
- 未接入 `runtime/frida` 的 bundle/smoke/metrics/多进程；这是独立的 DSL → Frida 安装路径。

## 参考

- Frida `NativeCallback` / `SystemFunction`（hook 回调与原函数调用）；
- 原 VulGate 语义：规则返回 PASS/BLOCK，动作目录，`value` 观察槽位；
- selector 偏移语义沿用 `build/declarative20-specs` 的 app profile layout。
