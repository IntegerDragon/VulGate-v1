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

## 验证

```sh
python -m runtime.dsl.vm_validate
```

服务器最近结果：**26/26 VM 场景通过**（20 BLOCK + 5 PASS + 1 memory）。

真实 nginx 1.31.6：

- CVE-2026-27654 DAV COPY：204 → 405；
- CVE-2026-93479 dynamic script：200 → 500；
- CVE-2026-42945 rewrite：302 → 500。

## 限制

- VM 只读，action writes 未实现；
- DSL→VM 目前支持 20 例子集：无循环、无 observers/maps；
- Frida 回调仍只适合单线程；
- 自动 offset 依赖可读 ELF + `nm`。
