# autoshield 开发计划

本文档根据 `docs/human/DESIGN.md` 和 `docs/human/IMPL.md` 制订，用于指导论文最小原型实现。当前旧设计已经废弃，后续代码、文档、脚本和实验产物统一使用 `autoshield` 命名。

## 总体目标

autoshield 的目标是在漏洞函数入口处完成攻击判断，并在原函数体执行前阻断危险调用。系统不在函数中部退出，不做运行时状态回滚，不修改目标程序真实状态。核心路径是：离线生成只读 Shadow eBPF 程序，验证其安全性；运行时入口拦截目标函数，提取寄存器和参数；自定义 eBPF VM 只读模拟漏洞触发谓词；根据 PASS、BLOCK、UNKNOWN 三种结果决定放行、返回错误码或降级阻断。

最小原型优先证明两个问题。第一，LLM 生成的 shadow 程序可以被自动验证为只读且可控。第二，相比直接禁用整个函数的 SWRR，autoshield 能在用户态 demo 中阻断 PoC，同时保留更多正常请求。

## 阶段一：仓库与命名整理

本阶段只做新原型需要的最小骨架，不迁移旧 VulGate/VulShield 逻辑。

1. 建立新目录结构。
   目标目录为 `offline/`、`runtime/`、`examples/`、`tests/`、`docs/`。旧目录中和新方案无关的 policy、rollback、symbolic、restriction、isolation 实现不再作为主线依赖。

2. 统一项目命名。
   文档中统一使用 `autoshield`。C 代码中的公共类型和函数不使用项目名前缀，优先使用 `shadow_*`、`hook_*`、`run_ebpf_vm` 等语义命名。生成产物文件名使用 `autoshield_*`。

3. 建立最小构建入口。
   根目录保留一个简单 `Makefile` 或脚本，支持构建用户态 runtime、offline verifier、用户态 demo。

验收标准是：仓库中可以看到新原型目录，`make` 或 `make user` 能构建用户态最小目标，README 中不再把旧系统作为当前实现主线。

## 阶段二：离线生成与验证模块

本阶段实现 `offline/`，输出可部署的只读 Shadow eBPF 字节码和验证报告。

1. 实现 `offline/template.c`。
   模板只暴露一个 shadow 入口函数，输入为运行时上下文结构，输出为 PASS、BLOCK 或 UNKNOWN。模板只允许读取参数、对象字段和受控 helper 返回值，不允许写目标内存、不允许分配资源、不允许加锁。

2. 实现 `offline/gen_rule.py`。
   输入包括漏洞代码片段、补丁 Diff、Sanitizer 报告、Crash Trace、PoC 描述和正常样本描述。脚本调用 LLM 生成只读判断逻辑，再填入 `template.c`。第一版不做复杂自动切片，只要求能通过 prompt 和模板生成可编译的 shadow C 文件。

3. 实现 shadow C 到 eBPF 字节码的编译流程。
   优先使用 clang 生成 eBPF object，再从 object 中提取目标 section 的指令。输出目录建议包含 `shadow.c`、`shadow.o`、`shadow.bin`、`manifest.json` 和 `verify_report.json`。

4. 实现 `offline/verifier.py`。
   检查器扫描 eBPF 指令并拒绝危险行为。第一版必须拒绝 store 指令、原子操作、向后跳转、未知 helper、非白名单 helper、越界跳转、过长程序和非法退出。允许的 helper 只保留安全读、参数读取和必要的常量查询。

5. 实现验证报告。
   每次生成都记录指令数、分支数、helper 调用列表、是否包含写操作、是否包含向后跳转、最终结论和拒绝原因。

验收标准是：给定一个简单越界访问示例，`gen_rule.py` 能生成 shadow C 和 eBPF 字节码；`verifier.py` 能接受只读版本，并拒绝包含写操作或死循环的坏样例。

## 阶段三：运行时公共层与 VM

本阶段实现 `runtime/autoshield.h`、`runtime/vm.c` 和 `runtime/safe_mem.c`，形成平台无关的数据平面核心。

1. 定义统一上下文。
   `autoshield.h` 中定义寄存器快照、函数参数、shadow 程序、VM 配置、执行统计和裁决结果。裁决结果固定为 `SHADOW_PASS`、`SHADOW_BLOCK`、`SHADOW_UNKNOWN`、`SHADOW_VM_ERROR`。

2. 接入自定义 eBPF VM。
   如果已有 uBPF-like VM，优先复用其解释器核心，只补齐 autoshield 需要的上下文、helper、统计和错误码。VM 必须支持指令步数上限，防止异常程序长时间运行。

3. 实现只读 helper。
   VM 中只注册白名单 helper。核心 helper 是安全内存读取、读取函数参数、读取寄存器值、读取受控对象字段。helper 不提供任何写内存、分配、锁、引用计数、系统调用或持久状态修改能力。

4. 实现 `safe_mem.c`。
   用户态版本通过 SIGSEGV 容错读取无效地址。当前 runtime 不保留 kernel hook 占位实现。

5. 实现裁决包装函数。
   提供 `run_ebpf_vm(ctx, program, policy)`，有 JIT entry 时调用 JIT，否则调用 interpreter，并返回裁决。UNKNOWN 的默认策略应可配置，论文实验中至少支持 `unknown_block` 和 `unknown_swr_disable` 两种。

验收标准是：不依赖 hook 的单元测试可以直接构造上下文，运行 shadow 字节码，得到 PASS、BLOCK、UNKNOWN，并记录指令数和安全读取次数。

## 阶段四：Linux 用户态闭环

本阶段先跑通最小端到端链路，因为用户态调试成本最低。

1. 实现 `runtime/hook_user.c`。
   第一版优先支持 LD_PRELOAD / dyld interpose 进入目标函数入口。每个 hook 目标对应一个专用 handler stub，由 stub 直接按已知 ABI 打包参数、调用 `run_ebpf_vm`，再决定放行或直接返回错误码。当前 demo 可以手写 stub；后续性能路径可以在安装 hook 时动态生成 stub，避免运行时按目标名做 dispatch。

2. 建立 `examples/user_demo/`。
   demo 包含一个存在漏洞的 C server 或命令行程序，一个 PoC 请求，一个正常请求，一个 shadow 规则和启动脚本。漏洞类型优先选择越界读写或整数溢出，便于证明入口参数足以判断风险。

3. 实现用户态阻断逻辑。
   当 VM 返回 BLOCK 时，hook 不进入原函数体，直接设置返回值。当返回 PASS 时，正常调用原函数。当返回 UNKNOWN 时，根据策略阻断或降级为禁用该函数。

4. 记录运行日志。
   日志至少包含目标函数名、裁决结果、VM 指令数、安全读取次数、返回码和是否进入原函数。

验收标准是：运行 PoC 时 autoshield 在函数入口阻断攻击；运行正常请求时目标程序行为保持正常；关闭 autoshield 后 PoC 能触发漏洞或异常路径。

## 阶段五：测试脚本与评估

本阶段实现 `tests/` 中三类实验脚本，产出论文可引用的结果。

1. 实现 `tests/test_security.py`。
   对每个 demo 运行 PoC，断言 autoshield 开启时攻击被阻断，关闭时能复现漏洞或异常路径。测试覆盖越界读写、释放后重用、整数溢出中的至少两类。

2. 实现 `tests/test_robustness.py`。
   运行正常请求集，确认误杀率。再注入坏 shadow 程序，包括非法指针读取、写指令、向后跳转和未知 helper，验证 verifier 或 VM 能拒绝或安全失败。

3. 实现 `tests/test_perf.py`。
   对比无防护、SWRR 直接返回、Shadow Execution 三种模式。记录平均延迟、p95、p99、吞吐量、VM 指令数、安全读取次数和 BLOCK/PASS/UNKNOWN 分布。

4. 统一结果格式。
   所有测试输出到 `eval/results/`，格式优先使用 JSON 或 CSV。每次实验记录 git commit、平台、编译参数、目标程序、规则文件和运行时间。

验收标准是：一条命令可以跑完用户态 demo 的安全性、健壮性和性能测试，并生成同样格式的结果。

## 阶段六：真实 CVE 适配

本阶段用于论文评估，不阻塞最小原型。

1. 选择 CVE。
   优先选择触发条件可在入口通过只读分析判断的用户态漏洞。漏洞类型优先覆盖越界访问、整数溢出、UAF。

2. 为每个 CVE 建立 bundle。
   每个 bundle 包含漏洞说明、PoC、正常请求、shadow C、shadow 字节码、验证报告、运行脚本和预期结果。

3. 记录不可适用案例。
   对必须依赖函数内部复杂副作用之后状态才能判断的漏洞，明确标记为 out-of-scope。该类案例不强行用中部拦截解决。

验收标准是：至少完成两个真实 CVE 的端到端阻断；每个 CVE 有可复现实验脚本和验证报告。

## 推荐实现顺序

第一轮先完成用户态最小闭环：`offline/template.c`、`offline/verifier.py`、`runtime/autoshield.h`、`runtime/vm.c`、`runtime/safe_mem.c`、`runtime/hook_user.c`、`examples/user_demo/`、`tests/test_security.sh`。

第二轮补齐自动生成和健壮性：`offline/gen_rule.py`、坏样例验证、SIGSEGV 安全读测试、误杀测试和基础性能测试。

第三轮适配真实 CVE 并整理实验结果：固定 bundle 格式，跑安全性、误杀和性能对比，生成论文表格所需数据。

## 风险与约束

autoshield 只处理可以在函数入口通过只读状态判断的漏洞。若判断必须依赖函数内部真实副作用之后的状态，该漏洞不属于当前方案适用范围。

LLM 只参与离线 shadow 程序生成，不属于运行时可信组件。最终是否部署由 verifier、样本验证和人工审核共同决定。

运行时 VM 和 helper 必须保持只读。任何写目标内存、分配资源、加锁、引用计数修改、调用危险 helper 的需求，都应视为设计偏离。

UNKNOWN 策略必须显式配置。安全优先实验默认阻断；功能优先实验可以降级为 SWRR 式粗粒度禁用，并单独统计。

当前实现以用户态最小原型为目标，不追求生产级热补丁、安全卸载、完整 ABI 覆盖或所有架构兼容。
