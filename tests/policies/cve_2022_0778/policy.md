---
schema_version: "vulgate.policy.v0.2"
protection_boundary: "function_entry"
policy_id: "cve_2022_0778"
cve_or_bug_id: "CVE-2022-0778"
target_function: "BN_mod_sqrt"
abi: "BIGNUM *"
unsafe_action:
  value: 0
  error: "BN_R_NOT_A_SQUARE"

unknown_action:
  value: 0
  error: "BN_R_NOT_A_SQUARE"

error_action:
  value: 0
  error: "BN_R_NOT_A_SQUARE"
  disable_policy: true

max_steps: 8192
max_call_depth: 4
evidence:
  vulnerable_condition: "Old BN_mod_sqrt may search past the Tonelli-Shanks bound e for malformed modulus inputs."
  caller_contract: "NULL is checked and intermediate BIGNUMs are freed."

---

```python
NULL = 0
BN_NOT_A_SQUARE = "BN_R_NOT_A_SQUARE"
MAX_BN_BITS = 16384

@monitor("BN_mod_sqrt", phase="enter", order="before_intercept")
def bn_sqrt_monitor(ctx, in_, a, p, bn_ctx):
    ctx.set(status="unknown")

    require(a.readable and p.readable)
    require(p.bit_length <= MAX_BN_BITS)

    b, e = setup_tonelli_state_ro(a, p)
    assert_model(0 < e <= p.bit_length)

    if e <= 1:
        ctx.set(status="unsafe")
        return

    t = bn_mod_sqr_ro(b, p)
    for _ in bounded_range(1, e):
        if bn_is_one_ro(t):
            ctx.set(status="safe")
            return
        t = bn_mod_mul_ro(t, t, p)

    ctx.set(status="unsafe")


@intercept("BN_mod_sqrt")
def bn_sqrt_intercept(ctx, in_, a, p, bn_ctx):
    facts = ctx.get()

    if facts.status == "safe":
        return PASS
    if facts.status == "unsafe":
        return BLOCK(value=NULL, error=BN_NOT_A_SQUARE)
    if facts.status == "error":
        return FALLBACK(value=NULL, error=BN_NOT_A_SQUARE, disable_policy=True)
    return FALLBACK(value=NULL, error=BN_NOT_A_SQUARE)


@check(
    "cve_2022_0778",
    max_steps=8192,
    max_call_depth=4,
    on_unknown=SWRR(value=NULL, error=BN_NOT_A_SQUARE),
    on_error=SWRR(value=NULL, error=BN_NOT_A_SQUARE, disable_policy=True),
)
def audit_bn_sqrt(record):
    assert_action(
        target="BN_mod_sqrt",
        value=NULL,
        error=BN_NOT_A_SQUARE,
        abi="BIGNUM *",
        caller_contract="NULL is checked and intermediate BIGNUMs are freed",
        retry="non_retryable_for_same_parameters",
    )
    require(record.monitor.target_state_writes == 0)
    require(record.monitor.bn_ctx_mutated is False)
    require(record.monitor.loop_has_bound is True)
    return SAFE
```
