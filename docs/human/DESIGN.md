### 核心设计

当前，LLM 正在显著加速系统漏洞发现过程。Linux、FreeBSD 等复杂系统中的严重漏洞，可能在短时间内被连续发现，相关 PoC 也会迅速扩散。在传统修复流程中，正式补丁通常需要较长时间完成正确性、兼容性与回归测试；而在补丁发布和完成部署之前，系统始终处于高风险暴露窗口。因此，如何在不重启、不重编译、不引入高风险修改的前提下，快速、安全地阻断漏洞利用，是一个重要的研究问题。

已有工作已经尝试通过临时防护机制缓解这一问题。Talos 提出了 Security Workarounds for Rapid Response（SWRR）概念，即在函数入口进行插桩；一旦 workaround 被启用，就直接让目标函数返回错误码，从而临时禁用存在漏洞的函数。该方法实现简单，安全性较高，因为它避免了修改函数内部状态；但其代价是屏蔽整个函数，可能显著影响正常功能。如果漏洞函数位于关键执行路径，直接禁用甚至可能导致系统整体不可用。

PET 基于 sanitizer 报告，在漏洞指令前利用 eBPF 动态插桩，使程序先执行到危险点，再在危险操作发生前进行拦截。为了解决函数中部拦截带来的副作用问题，PET 通过静态分析识别需要配对恢复的操作，并结合运行时 checkpoint-restore，回滚内存分配、锁获取、引用计数增加等状态变化。该方法能够更精确地阻断漏洞触发，且无需内核重启或重编译；但其核心依赖于副作用回滚，而回滚语义本身复杂且风险较高，容易因静态分析不完整或恢复逻辑错误，引入新的稳定性和安全问题。

VulShield 通过静态分析生成漏洞约束表达式，并优先尝试在函数入口或返回点部署检测；如果表达式不能放到这些边界，VulShield 还会寻找同一函数中已有的错误处理基本块并跳转过去。对于 UAF 和竞态等不易用表达式表示的漏洞，VulShield 另外提供 Quarantine and Sweeper（QS）与 Delayed Execution until Completion（DEC）。因此，不能把 VulShield 简化为“只能在函数入口提前返回”。它的主要边界是：表达式由变量、运算符、逻辑判断和少量白名单函数调用构成；复杂路径语义不能总是压缩成这类约束；跳到函数内部错误块又要求该错误块在当前资源阶段确实合法。论文对 1,458 个历史漏洞补丁进行人工模式分析时，判定其中 825 个（56.6%）可支持，也说明该方法并非覆盖任意复杂触发条件。PET 和 VulShield 还依赖 sanitizer 报告、LLVM/SVF 分析、符号与调试信息以及地址级映射，整体生成和审查链较长。

从安全性角度看，在函数入口判断漏洞是否会触发，并在确认风险后直接让漏洞函数返回，是最安全的一类思路。因为这种方式不需要执行目标函数内部的危险路径，不涉及真实状态修改，也不需要在函数执行中途进行内存回滚或资源恢复。其核心挑战在于：如何在函数入口获得足够的程序语义，从而准确判断当前调用在后续执行中是否真的会触发漏洞。

为此，我们提出一种基于自定义 eBPF VM 的模拟执行机制，即 Shadow Execution。该方案在函数入口运行漏洞相关的只读语义切片，对从当前入口到危险点的关键计算进行无副作用模拟。与仅检查入口参数或少量条件的约束表达式不同，Shadow Execution 可以包含有界分支、循环、跨过程只读调用和临时影子状态，从而提前推断当前输入与相关系统状态是否会到达漏洞触发点。它不复制整个原函数：只保留影响漏洞谓词的控制流和数据流。对于内存写入、状态更新、锁操作、引用计数修改等副作用，系统只能在私有影子状态中建模，不能作用于真实目标状态。

进一步地，系统可以在多个相关函数入口部署 Observer 程序，用于模拟关键语义并收集漏洞判断所需的上下文状态。这些 Observer 仅作为只读分析模块运行，不改变系统真实状态。随后，系统在合适的目标函数入口部署 Interceptor；Interceptor 根据 Observer 收集到的状态信息以及模拟执行结果，判断当前调用是否危险。若模拟结果表明该调用会触发漏洞，则 Interceptor 直接返回错误码或安全返回值；否则允许目标函数正常执行。

该方案的核心优势在于：优先把真实拦截动作放在函数调用边界，同时提升边界处的漏洞判断能力。相比 SWRR，它不必无条件禁用整个漏洞函数；相比 PET，它不在危险指令处停止已经产生副作用的执行，也不依赖通用 checkpoint/rollback；相比 VulShield 的表达式路径，它可以执行更复杂的只读路径语义。对于父函数执行到中段后才出现的关键条件，系统不直接从父函数中段退出，而是尝试拦截即将被调用的子函数，让子函数返回其已有错误，由父函数原有错误处理路径释放之前获得的资源。这个能力仍受严格前提约束，并不等于任意中段漏洞都能处理。

LLM 的任务不是重写一个可替换原函数的补丁，而是根据漏洞报告、补丁 Diff、Sanitizer trace 和程序切片生成“漏洞相关语义等价”的只读检查函数。生成物随后编译到项目自定义的 eBPF VM 中运行；VM 与 Linux 原生 eBPF verifier 无关，需要由项目自己的 Verifier 限制读集合、循环上界、调用图、指令数和返回动作。LLM 只产生候选程序，不能自行证明候选程序正确。


### 实现思路

1. 基于成熟机制的函数入口拦截    
拦截机制本身并非本方案的研究重点，我们主要通过按需二进制重写（On-demand Binary Rewrite）或 Inline Hook 技术来实现。在 Linux 系统中，可直接复用 KProbe/Uprobe、fentry 等成熟基础设施；在其他系统中，可借助 Frida 或自定义 Trampoline 机制。具体而言，系统在目标函数入口处修改跳转逻辑，使控制流在原函数主体执行之前进入分析模块，从而在不破坏原函数栈帧和执行语义的前提下完成安全检查。

2. 借助 LLM 与程序切片的只读影子执行（Shadow Execution）    
方案的核心在于构建一个无副作用的只读影子执行逻辑，其完整生命周期包含生成、验证与运行三个阶段。

切片与生成：系统首先根据补丁 Diff、Sanitizer 报告、Crash Trace 或 PoC 定位漏洞触发点，并以触发条件为目标进行后向切片（Backward Slicing）。在此过程中，引入 LLM 辅助理解跨函数调用、复杂宏定义和数据结构，抽取漏洞触发所需的关键条件、数据依赖和只读状态依赖，进而生成精简的 Shadow eBPF 程序。该程序不模拟完整函数执行，不包含内存写、资源分配、锁操作或引用计数变化等真实副作用。

安全验证：生成的 Shadow eBPF 必须经过严格审查。系统通过静态覆盖检查、PoC 与正常样本的差分验证，以及自定义 Verifier 校验，确保该程序包含必要的漏洞判断逻辑，同时禁止真实写操作、危险 Helper 调用、非受控循环和越界访问。

运行与裁决：运行时，Interceptor 在目标函数入口执行只读检查，仅通过读取入参和必要系统状态来计算漏洞触发谓词。若判定会触发漏洞，则直接返回错误码或安全值；若判定安全，则放行执行原函数；若因状态不足或切片无法表达导致无法判定，即返回 UNKNOWN，则根据预设策略阻断，或降级为 SWRR 式的粗粒度禁用。

### 复杂触发条件与跨过程安全失败

两个聚焦案例和完整的 `monitor/check/intercept` Patch DSL 见 [PATCH_DSL_CASE_STUDIES.md](PATCH_DSL_CASE_STUDIES.md)。本节保留总体设计与扩展案例。

#### 1. 为什么“等价执行一遍”不能理解为复制整个函数

完整复制原函数会带来三个问题：一是把无关业务逻辑、循环和外部依赖一并带入 Policy；二是可能再次实现同一个漏洞；三是资源分配、I/O、锁和随机数等调用无法在只读环境中忠实执行。因此，Shadow Execution 只要求对“是否会到达危险点”这一判定保持等价：

```text
真实函数入口状态
      │
      ├─ backward slice：保留影响危险点的分支、计算和只读数据
      │
      └─ Shadow check：PASS / BLOCK / UNKNOWN
```

跨过程调用分为三类：

1. 纯函数或只读函数：生成对应的只读模型，可以正常调用；
2. 有副作用但返回值可由入口快照确定：只计算返回值，不执行副作用；
3. 返回值依赖 I/O、调度、分配成败或不可观测竞态：不得猜测，返回 `UNKNOWN`，或者把真实 Interceptor 下移到该子函数的入口。

所有循环必须有静态上界或由 Verifier 强制的动态步数上界；所有调用必须位于无递归、有界深度的调用图中。影子堆、影子 cursor 和临时大整数都属于 Policy 私有状态，执行结束后整体丢弃。

#### 2. 安全失败边界（Safe Failure Frontier）

如果父函数已经分配内存、持有锁或增加引用计数，不能简单在父函数中段返回。系统应沿调用链寻找一个子函数边界 `F`，并同时证明：

1. 在 `F` 入口可以由参数、只读状态或影子前缀执行判定危险；
2. `F` 的返回类型存在明确错误值；
3. 父函数及更上层调用者已经有处理该错误的控制流；
4. 该错误路径会释放进入 `F` 之前获得的锁、内存、引用和事务状态；
5. 提前失败不会遗漏协议必须发生的副作用，也不会造成无限重试；
6. 从 `F` 入口返回与原错误发生时处于兼容的资源阶段。

满足这些条件的最早调用边界称为安全失败边界。运行时只在函数入口做两类动作：在顶层入口提前拒绝，或在安全失败边界让被调函数返回错误。系统不支持跳转到任意源代码行，也不声称能够通用回滚父函数已经产生的副作用。

```text
parent()
  acquire A
  allocate B
  ret = child(...)       ← Interceptor 位于 child 入口
  if (ret < 0)
      goto cleanup       ← 复用原程序的 A/B 清理路径
  dangerous_use(...)
```

#### 3. Python Policy DSL 草案

Python 只是生成 DSL，不在目标系统中直接解释执行。编译器把下面的受限语法降为有界 Policy IR，再由自定义 Verifier 检查。

```python
@monitor("func", phase="enter|exit")
def observe(...):
    """更新 AutoShield 私有、有界且原子的状态；不能写目标状态。"""

@check(
    max_steps=4096,
    on_unknown=SWRR(value=typed_error),
    on_error=SWRR(value=typed_error, disable_policy=True),
)
def predicate(...):
    """返回 SAFE、UNSAFE、UNKNOWN 或 ERROR。"""

@intercept("func")
def guard(...):
    """只在函数入口返回 PASS、BLOCK(error) 或 UNKNOWN。"""
```

`check` 同时承担漏洞判定、模型断言和故障回退声明，但不是“证明程序一定正确”。`require` 失败产生 `UNKNOWN`；Policy/adapter 不变量失败产生 `ERROR`；二者必须分别绑定显式回退。`intercept` 负责把 `UNSAFE` 映射为类型化错误；`monitor` 只在需要跨调用状态或遥测时使用。编译器禁止动态反射、异常捕获、递归、任意对象分配、文件/网络访问和未建模的 Python 库调用。完整四态语义、`assert_model/assert_action` 和两个案例见 [PATCH_DSL_CASE_STUDIES.md](PATCH_DSL_CASE_STUDIES.md)。

### 案例一：CVE-2022-0778——复杂循环条件不能只靠简单约束

OpenSSL `BN_mod_sqrt()` 使用 Tonelli-Shanks 算法寻找模平方根。旧代码在循环中寻找最小的 `i` 使 `b^(2^i) == 1`；恶意证书提供不满足算法素数前提的 `p` 时，循环可能永不终止。真实补丁不是增加一个简单的 `p != x` 判断，而是把搜索改成由 `e` 限制的循环，并在搜索失败时返回 `NOT_A_SQUARE`：

```c
for (i = 1; i < e; i++) {
    t = (i == 1) ? mod_sqr(b, p) : mod_mul(t, t, p);
    if (is_one(t))
        break;
}
if (i >= e)
    goto error;
```

该条件包含大整数运算、循环状态和函数调用，不适合压成少量寄存器比较。Shadow Policy 可以执行漏洞相关的有界语义切片，但必须使用只读大整数 adapter，并设置与输入位数相关的成本上限：

```python
NULL = 0

@check(max_steps=8192)
def bn_mod_sqrt_would_fail(a: BigIntRO, p: BigIntRO) -> bool:
    # setup_tonelli_state 是只读模型，只返回影子大整数和算法变量 e。
    b, e = setup_tonelli_state(a, p)
    if e <= 1:
        return False

    t = mod_sqr_ro(b, p)
    for i in range(1, e):          # e 必须由 Verifier 证明有界
        if is_one_ro(t):
            return False
        t = mod_mul_ro(t, t, p)
    return True                    # 旧实现会继续搜索；正式补丁在此失败

@intercept("BN_mod_sqrt")
def guard_bn_mod_sqrt(ret, a, p, ctx):
    if bn_mod_sqrt_would_fail(a, p):
        return BLOCK(value=NULL, error="BN_R_NOT_A_SQUARE")
    return PASS
```

这里应阻断的是已证明会耗尽搜索上界的输入，而不是笼统拒绝所有非素数。还必须验证 OpenSSL 的调用者会在 `NULL` 后释放中间 `BIGNUM`、终止当前证书解析，并且错误栈语义与真实失败路径一致。若影子大整数预算不足，应返回 `UNKNOWN`，不能默认放行。

### 案例二：CVE-2020-25212——在子函数入口重放解析前缀

Linux NFS 客户端把目标 buffer 容量放在 `label->len` 中传入解码流程。旧版 `decode_attr_security_label()` 从 XDR 响应解析出 `len` 后先执行 `memcpy()`，并把 `label->len` 覆盖为已解析长度；更上层 `_nfs4_get_security_label()` 随后才比较原始 `buflen`，检查发生时越界复制已经完成。补丁把容量检查移动到复制点：

```c
len = be32_to_cpup(p);
p = xdr_inline_decode(xdr, len);
if (label->len && label->len < len)
    return -ERANGE;
memcpy(label->label, p, len);
```

在真实函数中，`len` 到函数中段才出现；直接等到 `memcpy()` 前拦截会遇到 XDR cursor 已经推进等副作用。这里可以把 `decode_attr_security_label()` 选作安全失败边界：在它的入口，用私有 cursor 重放只读解析前缀，提前算出本次复制真正使用的 `encoded_len`，危险时让该子函数直接返回 `-ERANGE`。其调用者已经包含 `status < 0 -> goto xdr_error` 的传播路径。

```python
ERANGE = -34

@check(max_steps=32)
def label_copy_overflows(xdr: XdrSnapshot, bitmap, label) -> bool:
    # typed adapter 把入口时的 label->len 暴露为 capacity，避免被后续覆盖。
    if label is None or label.capacity == 0:
        return False
    if not (bitmap[2] & FATTR4_WORD2_SECURITY_LABEL):
        return False

    cur = xdr.private_cursor()      # 不推进真实 xdr_stream
    cur.read_be32()                 # lfs
    cur.read_be32()                 # pi
    encoded_len = cur.read_be32()
    cur.require(encoded_len)        # 只做边界验证，不复制 payload
    return encoded_len < NFS4_MAXLABELLEN and label.capacity < encoded_len

@intercept("decode_attr_security_label")
def guard_security_label(xdr, bitmap, label):
    if label_copy_overflows(xdr.snapshot(), bitmap, label):
        return BLOCK(value=ERANGE)
    return PASS
```

这个例子体现了跨过程方案的价值：父级 NFS 请求可能已经建立了解码上下文，但我们不从父函数中段跳走，也不修改真实 cursor；被调函数从入口返回标准错误，原调用链负责退出和清理。部署前仍须做全调用点检查，确认 `-ERANGE` 不会被解释为可无限重试信号。

### 案例三：CVE-2017-2636——跨函数并发状态，而不是单次参数

Linux `n_hdlc` 的发送恢复路径与 flush 路径并发访问共享 `tbuf`，两条路径可能把同一 buffer 放回 free list 两次。真实补丁移除独立 `tbuf`，改用受锁保护的链表统一所有权。临时 Policy 不能只看某一次函数参数；它需要为每个 `n_hdlc` 对象维护私有的 in-flight 状态，并拒绝第二个冲突操作：

```python
@monitor("n_hdlc_send_frames", phase="enter")
def send_enter(n_hdlc, tty):
    state[n_hdlc].send_inflight += 1

@monitor("n_hdlc_send_frames", phase="exit")
def send_exit(n_hdlc, tty, result):
    state[n_hdlc].send_inflight -= 1

@intercept("flush_tx_queue")
def guard_flush(tty):
    n_hdlc = tty2n_hdlc_ro(tty)
    if atomic_read(state[n_hdlc].send_inflight) > 0:
        return BLOCK_VOID       # 跳过本次 flush，不进入冲突窗口
    return PASS
```

该示例只是机制草案，不代表当前实现已经可以部署。`flush_tx_queue()` 是 `void`，静默跳过可能违反调用者对“已经清空”的预期；如果改在可返回错误的 ioctl/write 边界阻断，又要验证 `-EBUSY` 或 `-EAGAIN` 不会形成忙重试。因此，Observer 能检测冲突只是判定正确性，最终还需要证明阻断动作正确。若找不到能够报告失败且调用者可接受的边界，本例只能作为粗粒度功能禁用或判为 `UNKNOWN`。

### 反例：CVE-2019-19073——让中间子函数返回错误并不总能解决

ath9k HTC 路径先分配并提交 `skb`，再调用 `wait_for_completion_timeout()`；timeout 后的旧代码直接返回而没有 `kfree_skb(skb)`。在这里强制让等待函数返回 timeout，恰好会更快进入存在泄漏的错误路径，不能形成安全失败边界。正确补丁必须在父函数内部释放已经分配的 `skb`。除非能在分配/提交之前安全拒绝整个操作，或存在另一个会触发完整清理的上层边界，否则该实例仍不适用于无副作用入口 Policy。

上述案例给出新的适用边界：需要到函数中段才能获得条件，不再一律判为不适用；如果条件可以由只读语义切片提前重放，或者能在一个经过验证的子函数错误边界失败，就可以纳入。若判断依赖不可预测的真实副作用，或错误路径本身缺少清理，则仍为 `UNKNOWN/out-of-scope`。

实现时，每个 Interceptor 必须携带目标函数 ABI、候选错误值、全调用点验证摘要和重试策略。通用的 `return -EACCES`、`return NULL` 或 `ERR_PTR(-EFAULT)` 都不能作为默认动作；返回值必须按具体函数类型和调用契约生成。

3. 模块自身的安全性与隔离保障     
为确保防护机制不引入新的攻击面，系统采用极小可信基（TCB）设计。模拟执行引擎，即自定义 eBPF VM，通过内存隔离机制部署在独立内存域中运行。Shadow 程序只能通过受控接口读取经过校验的参数、对象字段和必要系统状态，不能直接写入目标程序地址空间，也不能调用会改变系统状态的 Helper。Hook 模块尽量复用现有成熟机制，仅负责轻量级控制流转移；LLM 仅参与离线候选程序生成，不作为运行时可信组件。通过上述设计，系统在实现细粒度漏洞阻断的同时，最大程度降低防护模块自身的安全风险与稳定性风险。

### 参考证据

- [VulShield, NDSS 2025](https://www.ndss-symposium.org/ndss-paper/vulshield-protecting-vulnerable-code-before-deploying-patches/)：约束表达式、函数入口/返回点、内部错误块、QS/DEC，以及 56.6% 补丁模式支持率。
- [CVE-2022-0778 修复提交](https://github.com/openssl/openssl/commit/a466912611aa6cbdf550cd10601390e587451246)：为 `BN_mod_sqrt()` 搜索增加 `e` 上界。
- [CVE-2020-25212 修复提交](https://github.com/torvalds/linux/commit/b4487b93545214a9db8cbf32e86411677b0cca21)：把 label 容量检查移动到真实 `memcpy()` 前。
- [CVE-2017-2636 修复提交](https://github.com/torvalds/linux/commit/82f2341c94d270421f383641b7cd670e474db56b)：移除 racy `tbuf` 并统一 buffer 所有权。
- [CVE-2019-19073 修复提交](https://github.com/torvalds/linux/commit/853acf7caf10b828102d92d05b5c101666a6142b)：在 timeout 错误路径释放已分配的 `skb`。
