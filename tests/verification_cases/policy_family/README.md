# Conditional action domains and choice lifetime

This benign C task checks a capacity assertion and requires two calls with the
same input to return the same result. It contains no invalid memory operation.
The seed passes counts at most 4 and returns -1 for larger counts.

```sh
python -m tools.verification tests/verification_cases/policy_family/task.json \
  --expand-family tests/verification_cases/policy_family/seed.json \
  --family-selection fixed_table --output build/verification/family-fixed
python -m tools.verification tests/verification_cases/policy_family/task.json \
  --expand-family tests/verification_cases/policy_family/seed.json \
  --family-selection per_invocation --output build/verification/family-fresh
```

Add `--toolchain /path/to/toolchain.json` when needed. The expected expansion
status is `MAXIMAL_FOR_SEED` for both commands, after five queries each:

| Selection | Expected domains | Meaning |
|---|---|---|
| `fixed_table` | `[[0], [1, 2]]` | Either error value can be selected for the high-count region; the choice remains fixed for the root execution. |
| `per_invocation` | `[[0], [1]]` | The seed's error value must be retained; permitting both would allow the two calls to disagree. |

Decision 0 is PASS, 1 returns -1 and 2 returns -2. Region 0 has `count <= 4`;
region 1 has `count > 4`. Another seed can produce another maximal family.
Maximality means no single domain can grow within this basis while preserving
the requested obligations; it does not establish a globally largest family.

Each report's `accepted_family.path` names an ordinary-loadable policy file.
Pass it to `--policies` to independently verify the complete exported family.
`family.contract_status` and `family.policy_status` are both expected to be
`PROVED_FOR_HARNESS`. Changing the fixed family's selection to `per_invocation`
while keeping both errors must refute `contract.stable_return`.

The task has explicit GCC x86-64 unit flags and receives the supported native/GOTO
ABI checks. Overall CLI status remains UNKNOWN and exit code 2 because lifecycle
induction and executable runtime correspondence are separate pending obligations.
