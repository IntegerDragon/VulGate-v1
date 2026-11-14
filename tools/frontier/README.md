# Safe Failure Frontier demo

给出危险函数与**同一漏洞版本**的 C 源码，枚举函数入口的失败返回候选。当前后端是无需编译的源码启发式，输出供审查与 DSL 选点使用，不能直接作为内核部署证明。

```sh
python -m tools.frontier --func target --src target.c --src callers.c --src types.h --json
python -m tools.frontier tests/frontier_cases/entry_errno/case.json
make test-frontier
```

输入 manifest：

```json
{
  "id": "CVE-example",
  "dangerous_function": "target",
  "sources": ["target.c", "callers.c", "types.h"]
}
```

相对路径基于 manifest 所在目录。务必给出调用方及相关结构体定义：缺失 `struct socket`、`Qdisc_ops` 等布局时，同名成员不能可靠确定回调目标。不要混用修复前、修复后的代码。

输出 schema 2 保留 `intercept` / `return_value` 作为排序首项，真正的选择材料是 `candidates`。`sites` 是兼容字段，不代表这些重叠候选应同时安装。

| 字段 | 含义 |
| --- | --- |
| `candidate_id` | 源码哈希、函数位置、返回值及关系共同决定的标识 |
| `location` / `return_location` | 入口定义位置及返回值来源位置；后者也可能是一条 errno 赋值 |
| `caller_evidence` | 每个已建模调用点的位置、间接调用标记、接受的失败类别、未确认状态 |
| `caller_contract` | `confirmed_in_model` 或 `partial`，前者也不是完整的资源/别名证明 |
| `uncovered_runtime_callers` | **单个候选**不能覆盖的已建模运行时调用路径 |
| `covers_all_modeled_runtime_paths` | 仅对输入源码里的已建模调用成立 |
| `relation=creation` | 同一 ops 对象的初始化候选；还需验证创建是危险对象启用的必经路径 |
| `input_files` | 分析输入的 SHA-256，用于绑定审查结果 |
| `analysis.unresolved_conditionals` | 没有实际 Kconfig 时仍未解决的条件编译分支 |
| `analysis.enforceable` | 当前始终为 `false`，后端不会自动授权 ENFORCE |

`found` 表示候选集合覆盖了模型内的运行时路径；单个候选未必覆盖全部。`partial` 表示存在候选但仍有路径缺口。`insufficient_input` 表示输入/调用关系不足；`out_of_scope` 表示被当前规则拒绝或当前模型没有候选，不能外推为不存在任何安全方案。CLI 返回码：候选存在（包括 partial）为 0，out_of_scope 为 2，insufficient_input 为 3；输入格式错误为 2，缺失源码为 1。

**资源规则。** 检查具体对象及数量，而非只比较 `kmalloc/kfree` 名称。支持直接存入 owner 字段和确定的清理辅助函数实参绑定，互斥分支共同解锁，以及 `goto` 清理。不同对象的释放、条件性漏释放、未知别名不会作为完整清理证据。`__releases` / `__acquires` 注解，以及已建模的 init/destroy 初始化依赖，会阻止把该函数入口列为可跳过候选。

**宏规则。** 识别 syscall/BPF 定义宏、常见条件包装、简单函数别名、常量 `#if 0/1` 和 `#elif`；保留源码行号。未知 Kconfig 分支只收集假设，不等价于真实预处理。对具体部署，应按该内核的编译命令生成预处理源码，再做 LLVM/Clang CFG、返回值传播及所有权检查；当前没有声称接入 SVF。

复跑已人工审查的样例包：

```sh
python -m tools.frontier.benchmark /path/to/frontier-corpus/corpus.json --output build/frontier-replay.json
```

runner 先检查每份源码哈希，再比较**完整候选组合及状态**。新增、缺失候选都导致失败，新增候选需要重新审查。这个结果是固定基线的回归一致性，不是“漏洞修复准确率”。

设计与限制见 [FRONTIER_DESIGN.md](../../docs/ai/FRONTIER_DESIGN.md)。
