---
schema_version: "vulgate.policy.v0.2"
protection_boundary: "function_entry"
policy_id: "cve_2020_25212"
cve_or_bug_id: "CVE-2020-25212"
target_function: "decode_attr_security_label"
abi: "int"
unsafe_action:
  value: -34

unknown_action:
  value: -5

error_action:
  value: -5
  disable_policy: true

max_steps: 64
max_call_depth: 2
evidence:
  vulnerable_condition: "encoded_len exceeds label.capacity before memcpy in the NFS security label decoder."
  caller_contract: "negative status reaches xdr_error and aborts decode"

---

```python
EIO = -5
ERANGE = -34
NFS4_MAXLABELLEN = 4096

@monitor("decode_attr_security_label", phase="enter", order="before_intercept")
def nfs_label_monitor(ctx, xdr, bitmap, label):
    ctx.set(status="unknown")

    if label is None:
        ctx.set(status="safe")
        return

    if bitmap[2] & (FATTR4_WORD2_SECURITY_LABEL - 1):
        ctx.set(status="safe")
        return

    if not (bitmap[2] & FATTR4_WORD2_SECURITY_LABEL):
        ctx.set(status="safe")
        return

    snapshot = xdr.snapshot()
    require(snapshot.readable(12))

    capacity = label.capacity_at_entry
    assert_model(capacity >= 0)
    assert_model(capacity == 0 or label.label is not None)

    if capacity == 0:
        ctx.set(status="safe")
        return

    cur = snapshot.private_cursor()
    cur.read_be32()
    cur.read_be32()
    encoded_len = cur.read_be32()
    require(cur.can_read(encoded_len))

    if encoded_len >= NFS4_MAXLABELLEN:
        ctx.set(status="safe")
        return

    if capacity < encoded_len:
        ctx.set(status="unsafe")
    else:
        ctx.set(status="safe")


@intercept("decode_attr_security_label")
def nfs_label_intercept(ctx, xdr, bitmap, label):
    facts = ctx.get()

    if facts.status == "safe":
        return PASS
    if facts.status == "unsafe":
        return BLOCK(value=ERANGE)
    if facts.status == "error":
        return FALLBACK(value=EIO, disable_policy=True)
    return FALLBACK(value=EIO)


@check(
    "cve_2020_25212",
    max_steps=64,
    max_call_depth=2,
    on_unknown=SWRR(value=EIO),
    on_error=SWRR(value=EIO, disable_policy=True),
)
def audit_nfs_label(record):
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
    require(record.monitor.target_state_writes == 0)
    require(record.monitor.real_xdr_cursor_moved is False)
    require(record.intercept.shadow_replay is False)
    return SAFE
```
