# Patch DSL → VulGate Shadow VM

`runtime/dsl/` 将补丁 DSL 编译成 `runtime/vm.c` 可执行的 eBPF 子集字节码，
通过 Frida bridge 安装到用户态进程。默认**不再使用 JS 回调**；`--backend js`
仅保留作对照。

## 文件

| 文件 | 作用 |
|---|---|
| `parser.py` | DSL → `PatchSpec` |
| `vm.py` | behavior/selector/表达式 → VM 字节码 |
| `resolve.py` | 自动补 `offset`、解析 `global("...")` 绝对地址 |
| `vm_run.py` | Frida bridge + `vg_program_create` / `vg_run` / `Interceptor.replace` |
| `run.py` | 统一 CLI（默认 `--backend vm`） |
| `patches/*.vg` | 20 个 CVE 补丁 |
| `vm_validate.py` | 合成 fixture 的 VM 验证 |

## 用法

```sh
# 解析/显示挂载点
python -m runtime.dsl.run --dsl patch.vg --check

# 安装到运行中进程（默认 VM）
python -m runtime.dsl.run --dsl patch.vg --pid 1234 --duration 30

# spawn 并安装
python -m runtime.dsl.run --dsl patch.vg --spawn ./target --duration 30

# JS 后端对照
python -m runtime.dsl.run --dsl patch.vg --pid 1234 --backend js
```

## VM 编译

- 每个 mount 生成 `r0=0`（PASS）或 `r0=1`（BLOCK）的 VM 程序；
- `argN` → `get_arg` helper；
- `vg_read_u8/u16/u32/u64/pointer` → `safe_read_*` helper；
- `global("x")` → 安装期解析成绝对地址常量；
- 比较/逻辑/算术 → 条件跳转/ALU；
- BLOCK 后由安装器执行 action 返回值，PASS 调原函数。

## 程序级 map / observer

```text
map limits:
{
    capacity: 16
}

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

- `read_point` 用 `Interceptor.attach` 安装，只写 map，继续原函数；
- 拦截点用 `map["limits"]["key"]` 读取，值进入 guard 条件；
- map 由 `vg_map_pool_create` 创建，observer/guard 共享；
- 字符串 key 在编译期映射为 per-map 的 `u64` key id；
- VM helper：`MAP_SET(9)` / `MAP_GET(10)` / `MAP_PRESENT(11)` / `MAP_DELETE(12)`。

## 验证

```sh
python -m runtime.dsl.vm_validate
python -m runtime.dsl.vm_map_validate
```

服务器最近结果：**26/26 VM 场景通过**（20 BLOCK + 5 PASS + 1 memory）。
`vm_map_validate` 用户态 fixture：observer 写入 100，101 被 BLOCK、50 PASS，
`blocked=-73, passed=0, body_calls=1`。

真实 nginx 1.31.6：

- CVE-2026-27654 DAV COPY：204 → 405；
- CVE-2026-93479 dynamic script：200 → 500；
- CVE-2026-42945 rewrite：302 → 500。

## 限制

- VM 只读，action writes 未实现；
- DSL→VM 目前支持 20 例子集：无循环、无 callsite observer；
- map 只支持编译期字面量 key；
- Frida 回调仍只适合单线程；
- 自动 offset 依赖可读 ELF + `nm`。
