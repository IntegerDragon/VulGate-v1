# 20 个 DSL 补丁的官方粒度对齐状态

“官方粒度”指 VulGate 原始 `patch.yaml` 的 guard 函数 + 条件，不是厂商 upstream
安全补丁的逐行等价。当前 DSL→VM 无 action writes、无 thread-scoped map。

| CVE | 原始条件 | 当前 DSL | 状态 |
|---|---|---|---|
| 109618 | `activated==0 && throws==0 && uploads==0` | 同条件 | ✅ 对齐 |
| 109619 | `True` | 无条件 | ✅ 对齐 |
| 111497 | callsite observer + map 条件 | 已恢复 callsite/local/dynamic key/present/take | ✅ 单线程对齐；⚠️ map 非 thread-scoped |
| 15176 | `alias!=0 && uri_changed` | 同条件 | ✅ 对齐 |
| 27654 | `True` | 无条件 | ✅ 对齐 |
| 42055 | `True`（proxy_v2/grpc 两个函数） | 两个无条件 mount | ✅ 对齐 |
| 42533 | `True` | 无条件 | ✅ 对齐 |
| 42945 | `void regex_start_code` + writes | `rewrite_handler` 无条件 500 | ❌ 无 writes，无法对齐 |
| 47360 | `previous!=0` | 同条件 | ✅ 对齐 |
| 56153 | `True` | 无条件 | ✅ 对齐 |
| 56154 | `True` | 无条件 | ✅ 对齐 |
| 56449 | `True` | 无条件 | ✅ 对齐 |
| 57941 | `True` | 无条件 | ✅ 对齐 |
| 60005 | `captures!=0 && realloc_captures` | 同条件 | ✅ 对齐 |
| 63292 | `True` | 无条件 | ✅ 对齐 |
| 63686 | `True` | 无条件 | ✅ 对齐 |
| 9256 | `void regex_start_code` + writes | `rewrite_handler` 无条件 500 | ❌ 无 writes，无法对齐 |
| 93479 | `check_length + length != 0` + writes | `check_length + length != 0`，返回 -1 | ✅ 条件/挂载点对齐；⚠️ 无 writes，效果弱于 500 |
| 93479-fine | 更细：`end != 0 && end-pos < len` | `patches_fine/CVE-2026-93479.vg` | ✅ 比原始更细 |
| 93546 | `True` | 无条件 | ✅ 对齐 |
| 97205 | `blocked >= 250*unit` | 同条件 | ✅ 对齐 |

## 结论

- 18 个补丁在条件/挂载点维度对齐原始 patch；
- 42945 / 9256 因 `void + action writes` 无法对齐；
- 93479 已从粗粒度 `script_run` 恢复到 `check_length + length != 0`；
- 93479-fine 提供更细的真实边界条件；
- 111497 的单线程语义对齐，但 map 未实现 thread-scoped。

验证：

```sh
python -m runtime.dsl.vm_validate          # 24/24（排除 111497/93479）
python -m runtime.dsl.vm_brotli_validate    # 111497 observer
python -m runtime.dsl.vm_93479_validate     # 官方粒度 + fine
python -m runtime.dsl.vm_php_validate       # PHP 109618
python -m runtime.dsl.vm_map_validate       # map/consume
python -m runtime.dsl.vm_callsite_validate  # callsite/local
```
