# 复杂触发条件与中段判定的 Patch DSL 案例

本文用两个真实漏洞说明 AutoShield 相对现有临时防护工作的设计动机，并给出 Python 风格 Patch DSL。这里描述的是**待实现的设计**，不是当前 VulGate 原型已经支持的能力。当前原型仍主要支持单函数入口、标量参数和 `arg_gt` 规则，没有下文所需的跨过程调用、typed adapter、Observer 状态和 `@check` 运行时。

## 1. 结论

| 问题 | 案例 | 现有方法的主要限制 | AutoShield 设计 |
|---|---|---|---|
| 复杂触发条件难以压缩成约束表达式 | CVE-2021-23017（Nginx） | 危险条件涉及 DNS label、压缩指针链、两遍长度计算和路径相关的分隔符写入 | 在入口执行有界、只读的 DNS 解析语义切片 |
| 条件到函数中段才产生 | CVE-2020-25212 | 若直接在危险指令前退出，必须证明当前资源阶段存在合法错误路径；否则可能泄漏资源或破坏状态 | 在被调函数入口用私有 parser cursor 重放解析前缀，再返回被调函数已有错误 |

需要准确区分 VulShield 的能力边界：VulShield 不只是函数入口提前返回。其论文允许在函数入口/返回点返回错误，也可以跳到同一函数已有的错误处理基本块；对于 UAF 和竞态还提供 QS/DEC。本文所说的不足是：

1. 其表达式路径主要由变量、逻辑/算术运算和少量白名单函数组成，不能据此假定任意循环、解析器或跨过程路径语义都能表达；
2. 中段退出只有在目标错误块与当前锁、内存、引用和协议阶段匹配时才安全；VulShield 没有通用的任意副作用回滚机制；
3. VulShield 论文对 1,458 个补丁进行人工模式分析，判定 825 个（56.6%）可支持，这本身也说明支持范围是有边界的。

因此，下文案例用于说明表达能力和错误边界问题，不用于声称 VulShield 论文已经明确把某个 CVE 判为“不支持”。

## 2. 三个 DSL 原语

### 2.1 `@monitor`：收集跨调用只读上下文

`monitor` 挂在函数入口或出口，只能更新 AutoShield 私有状态，不能修改目标程序状态。

```python
@monitor("target", phase="enter", key="call_id")
def observe_enter(args):
    state[call_id].field = safe_read(args.field)

@monitor("target", phase="exit", key="call_id", always=True)
def observe_exit(result):
    del state[call_id]
```

约束：

- 状态必须有类型、容量和生命周期上界；
- 更新必须是原子的；
- `exit, always=True` 表示正常返回和异常返回都清理私有状态；
- 状态缺失、陈旧、容量耗尽或对象身份不确定时，后续 `check` 返回 `UNKNOWN`，不能猜测。

### 2.2 `@intercept`：在函数入口执行类型化动作

`intercept` 只能位于函数调用边界。它消费 `check` 的四态结果，并返回 `PASS` 或目标函数 ABI 允许的阻断动作。

```python
@intercept("target")
def target_intercept(args):
    verdict = run_check("cve_policy", args)
    return enforce(
        verdict,
        unsafe=BLOCK(value=-EINVAL),
    )
```

不允许存在通用的默认错误码。每个 `BLOCK` 都必须绑定目标 ABI、错误值、调用者处理路径和重试上界。

### 2.3 `@check`：判定、断言与故障回退原语

第三个原语选择 `check`，而不是直接采用 Python `assert`。普通 `assert` 失败只会让 Policy 异常退出，无法说明应该放行、阻断还是降级。`check` 返回四态结果：

| 结果 | 含义 | Interceptor 动作 |
|---|---|---|
| `SAFE` | 证据充分，判定不会触发目标漏洞 | `PASS` |
| `UNSAFE(reason)` | 证据充分，判定会触发目标漏洞 | 执行该 Policy 的类型化 `BLOCK` |
| `UNKNOWN(reason)` | 缺少数据、预算不足或状态陈旧 | 执行 `on_unknown` |
| `ERROR(reason)` | Policy 模型、VM 或 adapter 违反内部不变量 | 执行 `on_error`，并熔断该 Policy |

```python
@check(
    "cve_policy",
    max_steps=4096,
    on_unknown=SWRR(value=-EINVAL),
    on_error=SWRR(value=-EINVAL, disable_policy=True),
)
def cve_check(args):
    require(args.readable, "missing runtime evidence")
    assert_model(args.length >= 0, "shadow model invariant broken")
    assert_action(
        target="target",
        value=-EINVAL,
        caller_contract="all callers terminate or enter cleanup",
    )
    return SAFE
```

`check` 内部包含三种受限语句：

- `require(condition, reason)`：运行时证据前提。失败产生 `UNKNOWN`；
- `assert_model(condition, reason)`：Policy 自身不变量。失败产生 `ERROR`，禁止继续相信本 Policy；
- `assert_action(...)`：部署时错误动作契约。Verifier 必须从 ABI、调用图和人工审核清单中验证；验证失败则整个 Policy 不得进入 ENFORCE。

`on_unknown` 和 `on_error` 必须显式声明。允许的回退是：

1. `SWRR(value=...)`：使用已经独立验证过的粗粒度函数禁用动作；
2. `BLOCK(value=...)`：仅当该错误值对当前边界已经验证安全；
3. `OBSERVE_ONLY`：只记录，不阻断；只能用于试运行或明确允许 fail-open 的部署。

不提供通用 `recover()` 去释放目标锁或内存。因为 Policy 在函数入口运行，不应拥有目标资源；若父函数此前已经获取资源，必须依赖经过验证的子函数错误返回，让原程序自己的清理路径执行。

## 3. 案例一：CVE-2021-23017（Nginx）

### 3.1 漏洞与补丁

Nginx 内置 DNS resolver 的 `ngx_resolver_copy()` 会把 DNS wire-format 名称解压成普通字符串。函数先遍历 label 和压缩指针，计算需要分配的长度；分配完成后再遍历一次，把 label 内容和 `.` 写入目标 buffer。

攻击者能够伪造上游 DNS 的 UDP 应答时，可以构造特殊压缩名称，使第一遍计算得到的长度比第二遍实际写入少 1 字节。结果是 `ngx_resolver_copy()` 在堆 buffer 末尾写出一个额外的 `.`，导致 worker 崩溃或潜在的进一步利用。

第一遍长度计算的关键形态如下。`len` 从 `-1` 开始，每遇到普通 label 增加 `1 + n`；遇到压缩指针时只跳转，不增加长度：

```c
len = -1;
for (i = 0; i < 128; i++) {
    n = *p++;
    if (n == 0)
        goto done;

    if (n & 0xc0) {
        n = ((n & 0x3f) << 8) + *p;
        p = &buf[n];
    } else {
        len += 1 + n;
        p = &p[n];
    }
}
```

旧版第二遍在复制完 label 后读取下一个 token；只要下一个 token 非零，即使它是一个最终指向根标签的压缩指针，也会立即写入 `.`：

```c
ngx_strlow(dst, src, n);
dst += n;
src += n;

n = *src++;
if (n != 0) {
    *dst++ = '.';
}
```

当当前 label 后面是压缩指针，且指针链最终直接到达 `0` 根标签时，第一遍只为 label 本身计算空间，第二遍却额外写入句点，从而产生 1-byte heap overwrite。

官方补丁把句点写入移动到“开始复制下一个实际 label 之前”。如果压缩指针最终指向根标签，就不会写句点：

```c
if (dst != name->data) {
    *dst++ = '.';
}

ngx_strlow(dst, src, n);
dst += n;
src += n;
```

### 3.2 为什么是复杂条件案例

危险条件不能准确写成“响应中存在压缩指针”或“名称长度达到上限”：合法 DNS 名称同样广泛使用压缩指针。Policy 必须至少完成以下路径相关计算：

1. 从 `src` 开始跟随普通 label 和压缩指针；
2. 对压缩指针限制跳转次数并验证每个目标仍位于 DNS 响应内；
3. 复现第一遍的分配长度；
4. 复现漏洞版本第二遍的实际写入长度；
5. 只有在 `vulnerable_write_len > allocated_len` 时阻断。

VulShield 的表达式路径支持变量、算术/逻辑运算和少量白名单函数，但论文没有证明它能在一个约束中执行两遍 DNS 解压语义。AutoShield 的差异不是简单增加一个更长的布尔表达式，而是允许调用经过验证的只读 parser model，并由 Verifier 限制循环次数、安全读取和调用图。

### 3.3 Patch DSL

```python
NGX_OK = 0
NGX_ERROR = -1
MAX_DNS_POINTERS = 128

stats = percpu_state(
    calls=u64,
    blocked=u64,
    unknown=u64,
    model_errors=u64,
)


@monitor("ngx_resolver_copy", phase="enter")
def resolver_copy_enter(r, name, buf, src, last):
    stats.calls += 1


@check(
    "cve_2021_23017",
    max_steps=4096,
    max_call_depth=3,
    on_unknown=BLOCK(value=NGX_ERROR),
    on_error=BLOCK(value=NGX_ERROR, disable_policy=True),
)
def check_resolver_copy(name, packet: ByteSpanRO, src_offset: u32):
    assert_action(
        target="ngx_resolver_copy",
        value=NGX_ERROR,
        abi="ngx_int_t",
        caller_contract="all callers abort the current DNS answer",
        retry="bounded_by_resolver_timeout_and_retry_policy",
    )

    if name is None:
        return SAFE                    # 真实函数只校验，不执行复制

    require(packet.contains(src_offset, 1), "invalid DNS name offset")

    # 第一遍：复现漏洞函数用于 ngx_resolver_alloc() 的长度计算。
    allocated_len = -1
    pos = src_offset

    for _ in bounded_range(0, MAX_DNS_POINTERS):
        n = packet.read_u8(pos)
        pos += 1

        if n == 0:
            break

        if n & 0xC0:
            require(packet.contains(pos, 1), "truncated compression pointer")
            pos = ((n & 0x3F) << 8) | packet.read_u8(pos)
        else:
            require(n <= 63, "invalid DNS label length")
            require(packet.contains(pos, n), "label outside DNS response")
            allocated_len += 1 + n
            pos += n
    else:
        return UNKNOWN("compression pointer limit exceeded")

    if allocated_len < 0:
        return SAFE                    # 空名称，不分配也不复制

    # 第二遍：只累计漏洞版本会写入的字节数，不实际写目标内存。
    vulnerable_write_len = 0
    pos = src_offset
    n = packet.read_u8(pos)
    pos += 1

    for _ in bounded_range(0, MAX_DNS_POINTERS):
        if n & 0xC0:
            require(packet.contains(pos, 1), "truncated compression pointer")
            pos = ((n & 0x3F) << 8) | packet.read_u8(pos)
            require(packet.contains(pos, 1), "pointer outside DNS response")
            n = packet.read_u8(pos)
            pos += 1

        else:
            require(n <= 63, "invalid DNS label length")
            require(packet.contains(pos, n), "label outside DNS response")
            vulnerable_write_len += n
            pos += n

            require(packet.contains(pos, 1), "missing next DNS token")
            n = packet.read_u8(pos)
            pos += 1

            if n != 0:
                vulnerable_write_len += 1   # 旧代码立即写入 '.'

        if n == 0:
            break
    else:
        return UNKNOWN("second-pass pointer limit exceeded")

    assert_model(vulnerable_write_len >= 0, "negative write length")

    if vulnerable_write_len > allocated_len:
        return UNSAFE("DNS decompression writes past allocated name buffer")
    return SAFE


@intercept("ngx_resolver_copy")
def resolver_copy_intercept(r, name, buf, src, last):
    packet = ByteSpanRO(base=buf, end=last)
    src_offset = src - buf
    verdict = check_resolver_copy(name, packet, src_offset)

    if verdict.kind == SAFE:
        return PASS
    if verdict.kind == UNSAFE:
        stats.blocked += 1
        return BLOCK(value=NGX_ERROR)

    # UNKNOWN/ERROR 不在这里临时猜测，由 @check 声明的回退执行。
    return FALLBACK(verdict)
```

### 3.4 `check` 提供的正确性保证

- DNS label、指针字节或指针目标不可安全读取时返回 `UNKNOWN`；
- 两遍解析都受 128 次压缩指针上界和 VM 总步数上界约束；
- Policy 只累计长度，不调用 `ngx_resolver_alloc()`，也不写 `name->data`；
- 只有第二遍写入长度大于第一遍分配长度时才返回 `UNSAFE`，不会笼统拒绝所有压缩 DNS 名；
- `NGX_ERROR` 必须通过全部调用点的 DNS answer 终止、资源释放和 resolver 重试检查；
- Policy 自身故障时返回经过验证的 `NGX_ERROR` 并熔断新模型。

该 Policy 相当于额外执行两遍有界 DNS 名称解析。部署前必须测试 resolver 热路径开销，并限制单响应可执行的 Policy 总步数。

## 4. 案例二：CVE-2020-25212

### 4.1 漏洞与补丁

Linux NFS 客户端把目标 label buffer 的容量放在 `label->len` 中。旧版 `decode_attr_security_label()` 从 XDR 响应解析出 `len` 后，先按该长度执行 `memcpy()`，随后才覆盖 `label->len`；更上层 `_nfs4_get_security_label()` 最后才比较 `buflen`，此时越界复制已经发生。

旧代码：

```c
len = be32_to_cpup(p++);
p = xdr_inline_decode(xdr, len);
if (len < NFS4_MAXLABELLEN) {
    memcpy(label->label, p, len);
    label->len = len;
}
```

真实补丁把检查放到 `memcpy()` 前：

```c
if (label->len) {
    if (label->len < len)
        return -ERANGE;
    memcpy(label->label, p, len);
}
```

### 4.2 为什么是中段判定案例

`encoded_len` 不是 `decode_attr_security_label()` 的直接参数，它要在函数内部依次解析 `lfs`、`pi` 和 `len` 后才出现。如果等真实函数运行到 `memcpy()` 前再拦截，真实 XDR cursor 已经推进；如果父函数此前还持有其他资源，中段硬退还必须证明资源可以正确清理。

AutoShield 不在 `memcpy()` 前跳出，而是在 `decode_attr_security_label()` 的函数入口使用私有 cursor 重放只读解析前缀。若发现容量不足，就让该子函数从入口返回 `-ERANGE`。上层 `decode_getfattr_attrs()` 已有 `status < 0 -> goto xdr_error` 的错误传播路径。

这不是对 VulShield 的绝对不支持证明：VulShield 如果能生成相同条件，并证明中部直接返回或错误块与当前状态匹配，也可能处理该实例。该案例要说明的是，安全性不能只由“危险点前有一个 if”推出；还必须验证解析副作用、资源阶段和调用者错误契约。子函数入口重放提供了一个不修改真实 cursor 的替代边界。

### 4.3 Patch DSL

```python
EIO = -5
ERANGE = -34

stats = percpu_state(
    calls=u64,
    blocked=u64,
    unknown=u64,
    model_errors=u64,
)


@monitor("decode_attr_security_label", phase="enter")
def nfs_label_enter(xdr, bitmap, label):
    stats.calls += 1


@check(
    "cve_2020_25212",
    max_steps=64,
    on_unknown=BLOCK(value=EIO),
    on_error=BLOCK(value=EIO, disable_policy=True),
)
def check_security_label(xdr: XdrSnapshot, bitmap, label):
    assert_action(
        target="decode_attr_security_label",
        value=ERANGE,
        abi="int",
        caller_contract="negative status reaches xdr_error and aborts decode",
        retry="bounded_by_rpc_policy",
    )
    assert_action(
        target="decode_attr_security_label",
        value=EIO,
        abi="int",
        caller_contract="negative status reaches xdr_error and aborts decode",
        retry="bounded_by_rpc_policy",
    )

    if label is None:
        return SAFE                    # 真实函数不会执行 memcpy
    if bitmap[2] & (FATTR4_WORD2_SECURITY_LABEL - 1):
        return SAFE                    # 真实函数会先返回 -EIO
    if not (bitmap[2] & FATTR4_WORD2_SECURITY_LABEL):
        return SAFE

    require(xdr.readable(12), "cannot read XDR label header")

    # typed adapter 在函数入口读取 label->len；此时它仍表示目标容量。
    capacity = label.capacity_at_entry
    assert_model(capacity >= 0, "negative label capacity")
    assert_model(capacity == 0 or label.label is not None,
                 "nonzero capacity without destination buffer")
    if capacity == 0:
        return SAFE                    # 补丁语义：label->len == 0 时不复制

    cur = xdr.private_cursor()       # 不推进真实 xdr_stream
    cur.read_be32()                  # lfs
    cur.read_be32()                  # pi
    encoded_len = cur.read_be32()
    require(cur.can_read(encoded_len), "truncated XDR payload")

    if encoded_len >= NFS4_MAXLABELLEN:
        return SAFE                  # 真实函数不会执行 memcpy
    if capacity < encoded_len:
        return UNSAFE("label copy exceeds caller capacity")
    return SAFE


@intercept("decode_attr_security_label")
def security_label_intercept(xdr, bitmap, label):
    verdict = check_security_label(xdr.snapshot(), bitmap, label)

    if verdict.kind == SAFE:
        return PASS
    if verdict.kind == UNSAFE:
        stats.blocked += 1
        return BLOCK(value=ERANGE)
    return FALLBACK(verdict)         # UNKNOWN/ERROR -> -EIO
```

### 4.4 `check` 提供的正确性保证

- XDR 不可读或 payload 截断时，不把数据臆测成安全；
- 私有 cursor 保证 Policy 不改变真实解码进度；
- typed adapter 在入口固定读取 `label->len`，不依赖父调用与 RPC 回调共享 thread-local 状态；
- 非零容量却没有目标 buffer 说明模型不变量被破坏，产生 `ERROR` 并熔断 Policy；
- 漏洞命中返回补丁使用的 `-ERANGE`；Policy 自身故障返回已有解析错误 `-EIO`；
- `assert_action` 要求部署前证明所有调用点会终止本次解码并进入清理，而且 RPC 重试有上界。

## 5. 部署与正确性门禁

LLM 生成上述 DSL 后，不得直接进入 ENFORCE。至少需要以下门禁：

1. **静态 Verifier**：禁止目标写入、递归、无界循环、未注册 adapter 和超限状态；
2. **判定 Oracle**：漏洞样本必须得到 `UNSAFE`，正常样本必须得到 `SAFE`；
3. **模型差分**：在修复版上记录真实分支，与 Shadow `check` 结果进行差分；
4. **错误动作验证**：分析全部调用点，并用 fault injection 强制返回候选错误，检查锁、内存、引用、错误传播和重试；
5. **故障注入**：主动制造 safe-read 失败、状态缺失、步数耗尽和 adapter 错误，确认执行 `on_unknown/on_error`；
6. **部署阶段**：先 OBSERVE，再由旧策略 enforce、新策略 shadow，最后 canary enforce；
7. **熔断**：`ERROR`、异常拒绝率或重试放大超过阈值时，自动禁用新 Policy 并回到已验证回退。

`@check` 能保证的是：Policy 故障不会被误当作 `SAFE`，错误动作必须经过契约验证，并且存在显式回退。它不能数学证明漏洞判定绝对正确，也不能替代正式补丁。

## 6. CVE-2022-0778 与 CVE-2020-25212 逐行注释版 DSL

本节专门给出两个 Policy 的逐行注释版。注释解释的是 DSL 设计语义；其中 `BigIntRO`、`XdrSnapshot`、`SWRR`、`assert_action` 等尚未在当前原型中实现。

### 6.1 CVE-2022-0778 逐行注释

```python
NULL = 0  # BN_mod_sqrt() 返回 BIGNUM *；失败时使用空指针，而不是整数错误码。
BN_NOT_A_SQUARE = "BN_R_NOT_A_SQUARE"  # 指定与正式补丁一致的 OpenSSL BN 错误原因。
MAX_BN_BITS = 16384  # 限制影子大整数的最大位数，避免 Policy 本身成为 CPU/内存 DoS。

stats = percpu_state(  # 创建每 CPU 私有遥测，避免所有线程竞争同一个全局计数器。
    calls=u64,  # 记录 BN_mod_sqrt() 被 Policy 检查的总次数。
    blocked=u64,  # 记录被确认危险并阻断的调用次数。
    unknown=u64,  # 记录因证据或预算不足得到 UNKNOWN 的次数；可由运行时自动更新。
    model_errors=u64,  # 记录模型断言或 adapter 故障；可由运行时自动更新。
)  # 结束遥测状态定义；该状态只属于 AutoShield，不写 OpenSSL 内存。

@monitor("BN_mod_sqrt", phase="enter")  # 在真实 BN_mod_sqrt() 入口执行只读 Observer。
def bn_sqrt_enter(in_, a, p, ctx):  # 参数顺序对应 OpenSSL 函数 ABI；in_ 是可选输出 BIGNUM。
    stats.calls += 1  # 只增加 Policy 私有计数，不改变输入 BIGNUM、BN_CTX 或错误栈。

@check(  # 定义第三原语：四态漏洞判定、模型断言和故障回退。
    "cve_2022_0778",  # 为 Policy 指定稳定标识，供加载、遥测、回退和熔断使用。
    max_steps=8192,  # 限制 VM 总指令/步骤数，防止影子算法出现无界执行。
    max_call_depth=4,  # 限制只读 helper 调用深度，并禁止递归调用图。
    on_unknown=SWRR(  # 缺少证据或预算耗尽时，不把未知结果误当作安全。
        value=NULL,  # 回退为粗粒度拒绝本次 BN_mod_sqrt() 调用。
        error=BN_NOT_A_SQUARE,  # 同时使用经过验证的 OpenSSL 错误原因。
    ),  # 结束 UNKNOWN 回退动作。
    on_error=SWRR(  # Policy 模型或 VM 自身出错时执行更强的熔断回退。
        value=NULL,  # 模型故障时仍返回符合 BIGNUM * ABI 的空指针。
        error=BN_NOT_A_SQUARE,  # 错误栈适配器必须产生调用者能够识别的 BN 错误。
        disable_policy=True,  # 禁用发生内部错误的新 Policy，避免持续使用不可信模型。
    ),  # 结束 ERROR 回退动作。
)  # 结束 @check 配置。
def check_bn_mod_sqrt(a: BigIntRO, p: BigIntRO):  # 输入是只读 BIGNUM adapter，不能写真实 limb。
    assert_action(  # 部署前验证阻断返回值，而不是等线上触发后再猜测。
        target="BN_mod_sqrt",  # 声明错误动作作用于哪个真实函数。
        value=NULL,  # 声明候选返回值为 NULL。
        error=BN_NOT_A_SQUARE,  # 声明需要同步设置的 OpenSSL 错误原因。
        abi="BIGNUM *",  # Verifier 检查返回值类型与函数 ABI 一致。
        caller_contract="NULL is checked and intermediate BIGNUMs are freed",  # 要求全部调用者判空并释放中间对象。
        retry="non_retryable_for_same_parameters",  # 要求调用者不会使用相同恶意参数无限重试。
    )  # 结束错误动作契约；验证失败时 Policy 不得进入 ENFORCE。

    require(a.readable and p.readable, "BIGNUM cannot be read safely")  # safe-read 失败产生 UNKNOWN。
    require(p.bit_length <= MAX_BN_BITS, "shadow bigint budget exceeded")  # 超大模数超过预算时走回退。

    b, e = setup_tonelli_state_ro(a, p)  # 只读重放到漏洞循环前，计算影子变量 b 和搜索上界 e。
    assert_model(0 < e <= p.bit_length, "invalid Tonelli state")  # 数学状态不可能时产生 ERROR 并熔断。

    if e <= 1:  # 正式补丁在没有有效搜索区间时会走 NOT_A_SQUARE 错误路径。
        return UNSAFE("no valid Tonelli search interval")  # 旧代码可能越过相等检查并继续循环，因此阻断。

    t = bn_mod_sqr_ro(b, p)  # 在影子大整数中计算第一次 b^2 mod p，不调用真实 BN 写操作。
    for _ in bounded_range(1, e):  # 最多执行 e-1 轮；Verifier 必须证明 e 和总步数均有界。
        if bn_is_one_ro(t):  # 找到 t == 1 表示旧循环能够在正式补丁上界内正常终止。
            return SAFE  # 证据充分时允许真实 BN_mod_sqrt() 执行。
        t = bn_mod_mul_ro(t, t, p)  # 只在影子状态中计算下一次平方，不修改真实 BIGNUM。

    return UNSAFE("old BN_mod_sqrt would search past e")  # 上界内始终未到 1，判定旧实现存在不终止风险。

@intercept("BN_mod_sqrt")  # 在真实 BN_mod_sqrt() 函数体执行之前安装 Interceptor。
def bn_sqrt_intercept(in_, a, p, ctx):  # 接收与真实函数相同的 ABI 参数。
    verdict = check_bn_mod_sqrt(a, p)  # 执行上面的只读四态检查，不执行真实漏洞循环。

    if verdict.kind == SAFE:  # 只有证据充分的 SAFE 才允许进入原函数。
        return PASS  # 不改变参数、错误栈和控制流，继续执行真实 BN_mod_sqrt()。
    if verdict.kind == UNSAFE:  # UNSAFE 表示已经复现正式补丁的失败条件。
        stats.blocked += 1  # 更新 Policy 私有的阻断遥测。
        return BLOCK(value=NULL, error=BN_NOT_A_SQUARE)  # 返回类型化空指针并设置 BN 错误。

    return FALLBACK(verdict)  # UNKNOWN/ERROR 分别执行 @check 中声明的 SWRR 和熔断动作。
```

关键点是 `check` 并不简单判断“`p` 是否为非素数”，而是有界重放漏洞相关算法状态。`require` 失败不会被当作 `SAFE`，`assert_model` 失败则说明新模型本身不可信。

### 6.2 CVE-2020-25212 逐行注释

```python
EIO = -5  # Linux -EIO：用于 XDR 不可读、Policy UNKNOWN 或模型故障时的解析失败回退。
ERANGE = -34  # Linux -ERANGE：正式补丁在目标容量小于 encoded_len 时返回的错误。

stats = percpu_state(  # 为 NFS label Policy 创建每 CPU 私有遥测。
    calls=u64,  # 记录 decode_attr_security_label() 被检查的次数。
    blocked=u64,  # 记录因容量不足返回 -ERANGE 的次数。
    unknown=u64,  # 记录 XDR safe-read、预算或证据不足次数；可由运行时自动更新。
    model_errors=u64,  # 记录 typed adapter 或模型不变量错误；可由运行时自动更新。
)  # 结束私有状态定义；这些计数不修改 NFS、RPC 或 XDR 对象。

@monitor("decode_attr_security_label", phase="enter")  # 在目标子函数入口运行 Observer。
def nfs_label_enter(xdr, bitmap, label):  # 参数顺序对应真实内核函数 ABI。
    stats.calls += 1  # 只更新 AutoShield 遥测，不推进真实 xdr_stream cursor。

@check(  # 定义 NFS 漏洞的四态判定和显式故障回退。
    "cve_2020_25212",  # Policy 的稳定标识。
    max_steps=64,  # 只需解析三个 u32 和验证 payload，因此设置较小执行上限。
    on_unknown=BLOCK(value=EIO),  # XDR 数据不可安全读取时按已有解析错误阻断，不能默认放行。
    on_error=BLOCK(  # Policy/adapter 内部不变量失败时使用熔断回退。
        value=EIO,  # 返回 decode_attr_security_label() 已支持的负错误类型。
        disable_policy=True,  # 禁用故障 Policy，避免后续请求持续使用错误模型。
    ),  # 结束 ERROR 回退动作。
)  # 结束 @check 配置。
def check_security_label(xdr: XdrSnapshot, bitmap, label):  # xdr 是只读快照而不是真实可写 stream。
    assert_action(  # 验证漏洞命中时使用的正式补丁错误动作。
        target="decode_attr_security_label",  # 声明动作对应的真实内核函数。
        value=ERANGE,  # 容量不足时返回 -ERANGE。
        abi="int",  # Verifier 检查返回值符合 int ABI。
        caller_contract="negative status reaches xdr_error and aborts decode",  # 要求所有调用者终止本次解码。
        retry="bounded_by_rpc_policy",  # 要求 RPC 对相同失败的重试次数有上界。
    )  # 结束 -ERANGE 动作契约。
    assert_action(  # 单独验证 UNKNOWN/ERROR 使用的 -EIO 回退动作。
        target="decode_attr_security_label",  # 回退仍发生在同一个子函数入口。
        value=EIO,  # 使用函数已有的 XDR 解析错误返回值。
        abi="int",  # 确认 -EIO 与目标函数 int ABI 匹配。
        caller_contract="negative status reaches xdr_error and aborts decode",  # 要求上层进入 xdr_error。
        retry="bounded_by_rpc_policy",  # 防止错误返回造成无限 RPC 重试。
    )  # 结束 -EIO 动作契约。

    if label is None:  # 没有输出 label 对象时，真实函数不会执行危险 memcpy。
        return SAFE  # 允许原函数继续完成仅解析/校验路径。
    if bitmap[2] & (FATTR4_WORD2_SECURITY_LABEL - 1):  # 更早的未处理属性位存在时，真实函数会先返回 -EIO。
        return SAFE  # 本 Policy 不需要抢先阻断，因为危险 memcpy 不可达。
    if not (bitmap[2] & FATTR4_WORD2_SECURITY_LABEL):  # 响应没有 security-label 属性时不会进入复制分支。
        return SAFE  # 允许真实函数按正常无 label 路径返回。

    require(xdr.readable(12), "cannot read XDR label header")  # 至少需要安全读取 lfs、pi、len 三个 u32。

    capacity = label.capacity_at_entry  # typed adapter 在入口固定读取 label->len，此时它仍表示目标容量。
    assert_model(capacity >= 0, "negative label capacity")  # 不可能的负容量说明 adapter/类型模型错误。
    assert_model(  # 检查目标容量与目标指针之间的基本一致性。
        capacity == 0 or label.label is not None,  # 非零容量必须对应一个实际目标 buffer。
        "nonzero capacity without destination buffer",  # 不变量失败时产生 ERROR 并熔断 Policy。
    )  # 结束目标对象模型断言。
    if capacity == 0:  # 正式补丁在 label->len 为 0 时不会执行 memcpy。
        return SAFE  # 因为没有复制，所以不存在本 CVE 的越界写。

    cur = xdr.private_cursor()  # 克隆逻辑 cursor；后续读取不会推进真实 xdr_stream。
    cur.read_be32()  # 读取并跳过 lfs 字段，使影子 cursor 与真实解析顺序一致。
    cur.read_be32()  # 读取并跳过 pi 字段。
    encoded_len = cur.read_be32()  # 读取服务端控制的实际 label 长度，即漏洞比较所需变量。
    require(cur.can_read(encoded_len), "truncated XDR payload")  # 确认 payload 完整，否则返回 UNKNOWN/-EIO。

    if encoded_len >= NFS4_MAXLABELLEN:  # 过长 label 会走真实函数的 warning 分支而不执行 memcpy。
        return SAFE  # 对本越界复制漏洞而言该分支安全，可交给原函数处理。
    if capacity < encoded_len:  # 复现正式补丁位于 memcpy 前的核心容量检查。
        return UNSAFE("label copy exceeds caller capacity")  # 证据充分地判定会发生越界复制。
    return SAFE  # 容量覆盖实际复制长度，允许真实函数执行 memcpy。

@intercept("decode_attr_security_label")  # 在子函数入口安装 Interceptor，而不是在 memcpy 前中段跳出。
def security_label_intercept(xdr, bitmap, label):  # 接收真实函数的三个入口参数。
    verdict = check_security_label(xdr.snapshot(), bitmap, label)  # 使用私有 XDR 快照执行 check。

    if verdict.kind == SAFE:  # 只有证据充分的安全结果才能放行。
        return PASS  # 执行真实解析函数；Policy 没有改变真实 cursor。
    if verdict.kind == UNSAFE:  # 目标容量不足且危险 memcpy 在当前路径可达。
        stats.blocked += 1  # 更新 AutoShield 私有阻断计数。
        return BLOCK(value=ERANGE)  # 从子函数入口返回正式补丁使用的 -ERANGE。

    return FALLBACK(verdict)  # UNKNOWN/ERROR 根据 @check 配置返回 -EIO，并在 ERROR 时熔断 Policy。
```

关键点是 XDR 解析发生在 `private_cursor()` 中。真实函数尚未执行，因此 Policy 不需要回滚真实 cursor；返回 `-ERANGE` 后，由原调用链的 `status < 0 -> xdr_error` 负责终止本次解码。

## 7. 参考资料

- [VulShield, NDSS 2025](https://www.ndss-symposium.org/ndss-paper/vulshield-protecting-vulnerable-code-before-deploying-patches/)
- [CVE-2021-23017 记录](https://cveawg.mitre.org/api/cve/CVE-2021-23017)
- [Nginx CVE-2021-23017 官方公告](http://mailman.nginx.org/pipermail/nginx-announce/2021/000300.html)
- [Nginx CVE-2021-23017 官方补丁](http://nginx.org/download/patch.2021.resolver.txt)
- [CVE-2022-0778 记录](https://cveawg.mitre.org/api/cve/CVE-2022-0778)
- [OpenSSL CVE-2022-0778 修复](https://github.com/openssl/openssl/commit/a466912611aa6cbdf550cd10601390e587451246)
- [CVE-2020-25212 记录](https://cveawg.mitre.org/api/cve/CVE-2020-25212)
- [Linux CVE-2020-25212 修复](https://github.com/torvalds/linux/commit/b4487b93545214a9db8cbf32e86411677b0cca21)
