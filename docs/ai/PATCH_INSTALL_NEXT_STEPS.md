# 鐢ㄦ埛鎬佽ˉ涓佸畨瑁咃細瀹屾暣宸ヤ綔娓呭崟锛坴2锛?

鏃ユ湡锛?026-11-14銆傛湰鏂囧湪鏃╁厛鍚屾枃浠剁増鏈殑鍩虹涓婏紝鎸夆€滄簮鐮?鏋勫缓涓庤繍琛岀増鏈竴鑷淬€佽ˉ涓佸ぉ鐒跺彲鎸傝浇銆佸彧鍋氬彲琛屾€ф鏌モ€濈殑鏂板墠鎻愰噸鍐欍€?

## 0. 鍓嶆彁涓庢槑纭笉鍋氱殑浜?

鍓嶆彁锛堟湰娆″亣璁撅級锛?

1. **婧愮爜銆佺紪璇戦€夐」涓庣嚎涓婅繍琛岀増鏈竴鑷?*锛氫笉澶勭悊鐗堟湰婕傜Щ銆佷笉閲嶅缓鐩爣銆佷笉鍋氬彂琛岀増閫傞厤銆?
2. **琛ヤ竵鍦ㄧ紪鍐欐椂灏辨槸鍙寕杞界殑**锛氫笉鍋氳嚜鍔ㄥ垏鐐逛笂绉汇€佷笉鍋氬唴鑱旈€傞厤銆佷笉鍋?LTO/ICF 鑷姩绾犳銆?
3. **鎸傜偣鍙鎬ф鏌ュ彧鍥炵瓟鈥滆兘涓嶈兘鎸傗€?*锛氫笉鑳芥寕灏辫繑鍥為敊璇爜/閿欒淇℃伅骞跺仠姝㈠畨瑁呫€?
4. 涓嶅寘鍚鍙锋墽琛屻€佽ˉ涓佹纭€ч獙璇併€佽浼ょ粺璁°€?
5. 棣栬鐩爣鏄?Linux x86-64 鐨?C/C++ 鐢ㄦ埛鎬佸簲鐢紱鍏朵粬鏋舵瀯/璇█鍙畾涔夎竟鐣岋紝涓嶅湪鏈疆瀹炵幇銆?

鏄庣‘涓嶅仛锛?

- 鐗堟湰婕傜Щ妫€娴嬩笌鑷姩閫傞厤锛?
- 鍐呰仈鍑芥暟鑷姩澶栫Щ銆佸垏鐐硅嚜鍔ㄤ笂绉伙紱
- 浠绘剰璇█/杩愯鏃讹紙JIT锛夐€傞厤锛?
- 琛ヤ竵璇箟姝ｇ‘鎬ц瘉鏄庛€?

## 1. 鐩爣瀹氫箟

杈撳叆锛?

- `bundle`锛歚manifest.json`锛坓uards/observers/maps/artifact 鏍￠獙锛? `actions.json`锛堝姩浣滅洰褰曪級+ `guard-*.bin`锛圴M 瀛楄妭鐮侊級+ `bridge` 鏈湴搴擄紱
- 鐩爣锛氳繘绋嬶紙pid/琛ㄨ揪寮?鍚嶇О锛夋垨鍙墽琛屾枃浠讹紙鎵樼鍚姩锛夈€?

杈撳嚭锛堟瘡涓繘绋嬩竴浠斤級锛?

```json
{
  "pid": 1234,
  "status": "installed_verified | installed_unverified | failed",
  "code": "E_OK | E_*",
  "message": "human readable",
  "bindings": [{"id": "...", "module": "...", "address": "0x..."}],
  "effect": {"triggered": true, "decision": "BLOCK", "value": "-73"},
  "decisions": 0,
  "blocks": 0
}
```

鎴愬姛鏍囧噯锛?*瑁呬笂锛堝彲瑙ｉ噴锛夆啋 鐢熸晥锛堟湁瑙﹀彂璇佹嵁锛夆啋 鍙畨鍏ㄥ嵏杞?*锛涘け璐ュ繀椤荤粰鍑虹ǔ瀹氶敊璇爜涓庡彲璇诲師鍥狅紝涓斾笉娈嬬暀鍗婅鐘舵€併€?

## 2. 閿欒鐮佷笌缁撴灉妯″瀷锛圥0锛屾墍鏈夊悗缁伐浣滅殑鍦板熀锛?

### 2.1 CLI 閫€鍑虹爜

| 閫€鍑虹爜 | 鍚箟 |
|---|---|
| 0 | 鍏ㄩ儴鐩爣瀹夎鎴愬姛锛堜笖鑻ュ０鏄?smoke锛屽叏閮ㄨЕ鍙戞垚鍔燂級 |
| 2 | 鍙傛暟/鐢ㄦ硶閿欒 |
| 3 | bundle 鏈韩鏃犳晥锛坰chema/瀛楄妭鐮?鍔ㄤ綔鐩綍涓嶄竴鑷达級 |
| 4 | 鎸傜偣涓嶅彲鎸傦紙瑙ｆ瀽澶辫触銆丄BI 涓嶆敮鎸佺瓑锛?|
| 5 | 鏉冮檺/娉ㄥ叆澶辫触 |
| 6 | 鐩爣涓嶅尮閰嶏紙build-id/鍝堝笇/鏋舵瀯涓嶇锛?|
| 7 | 閮ㄥ垎鐩爣澶辫触锛坄--fail-fast` 涓嬩笉浼氬嚭鐜帮級 |
| 8 | 宸插畨瑁?閲嶅瀹夎 |
| 9 | smoke 鏈骇鐢熼鏈?BLOCK锛堝凡鍗歌浇锛岄櫎闈?`--smoke-warn-only`锛?|

### 2.2 鎸傜偣閿欒鐮?

| 閿欒鐮?| 瑙﹀彂鏉′欢 |
|---|---|
| `E_ARCH_UNSUPPORTED` | 鐩爣鏋舵瀯涓嶆槸 x64锛堟湰杞級 |
| `E_SCHEMA_INVALID` | bundle/鍔ㄤ綔鐩綍 schema 涓嶆敮鎸?|
| `E_MODULE_MISSING` | `manifest.module` 鍦ㄧ洰鏍囪繘绋嬩腑鎵句笉鍒?|
| `E_SYMBOL_MISSING` | 瀵煎嚭绗﹀彿涓嶅瓨鍦ㄣ€佽 strip |
| `E_OFFSET_INVALID` | 鍋忕Щ瓒婄晫/涓嶅彲鎵ц |
| `E_HOOK_NOT_ALIGNED` | 鎸傜偣鍦板潃涓嶆弧瓒虫浛鎹㈠墠鎻愶紙鍙€夋鏌ワ級 |
| `E_DUPLICATE_HOOK` | 涓や釜 hook 鎸囧悜鍚屼竴鍦板潃 |
| `E_HOOK_INVALID` | hook 缂?id銆乮d 閲嶅銆佺粨鏋勯潪娉?|
| `E_MAP_INVALID` | map 瀹氫箟闈炴硶锛堝閲忚秺鐣岀瓑锛?|
| `E_ARITY_UNSUPPORTED` | 鍙傛暟涓暟 >6 鎴栫被鍨嬩笉鍦ㄦ敮鎸侀泦鍚?|
| `E_RETURN_UNSUPPORTED` | 杩斿洖绫诲瀷涓嶅湪 `int/int64/pointer/void`锛堟湰杞級鎴栦笌鍔ㄤ綔涓嶇 |
| `E_ACTION_MISSING` | `action_id` 涓嶅湪鍔ㄤ綔鐩綍 |
| `E_ACTION_ABI_MISMATCH` | 鍔ㄤ綔绫诲瀷涓庤繑鍥炵被鍨?鍙傛暟绫诲瀷涓嶅尮閰?|
| `E_ACTION_WRITE_INVALID` | 鍔ㄤ綔鍐欏瓧娈电殑鐩爣鍙傛暟涓嶆槸 pointer 鎴栧亸绉?瀹藉害闈炴硶 |
| `E_ACTION_CALL_INVALID` | 鍔ㄤ綔闄勫甫璋冪敤锛坄calls`锛夌殑 module/symbol/鍙傛暟/once 闈炴硶鎴栦笉鍙В鏋?|
| `E_RULE_INVALID` | 瀛楄妭鐮佷负绌恒€侀暱搴﹂潪 8 鍊嶆暟銆佽秴涓婇檺銆乂M 鏍￠獙鎷掔粷 |
| `E_MAP_MISSING` | guard/observer 寮曠敤浜嗕笉瀛樺湪鐨?map |
| `E_OBSERVER_INVALID` | 瑙傛祴鐐规搷浣?閿?鍊煎０鏄庨潪娉?|
| `E_BRIDGE_ABI` | bridge 鐗堟湰涓嶅尮閰嶏紙`vg_abi_version`锛?|
| `E_ALREADY_INSTALLED` | 鍚屼竴杩涚▼宸插畨瑁呭悓 bundle |
| `E_TARGET_BUSY` | 鍗歌浇/瀹夎鏃朵粛鏈夊洖璋冨湪璺?|
| `E_INJECT_DENIED` | ptrace 鏉冮檺銆乊ama銆丩SM 鎷掔粷 |
| `E_TARGET_EXITED` | 瑙ｆ瀽/瀹夎鏈熼棿鐩爣閫€鍑?|
| `E_TARGET_MISMATCH` | 鐩爣鍝堝笇/build-id 涓?bundle 澹版槑涓嶇 |
| `E_SMOKE_FAILED` | 瀹夎鎴愬姛浣嗚Е鍙戦」娌℃湁浜х敓棰勬湡 BLOCK |

### 2.3 澶辫触璇箟

- **杩涚▼鍐呭師瀛?*锛氬厛鎶婃墍鏈?guards/observers 瑙ｆ瀽骞舵牎楠屽畬锛屽啀缁熶竴 `Interceptor.replace`锛涗换涓€椤瑰け璐ュ垯鏁磋繘绋嬪け璐ャ€佷笉鎸備换浣?hook锛坅gent 鐜版湁 `install` 宸叉寜姝ゅ疄鐜帮紝闇€鎵╁睍鍒?probe 涓庨敊璇爜锛夈€?
- **璺ㄨ繘绋嬬瓥鐣?*锛歚--fail-fast`锛堥粯璁わ細浠讳竴杩涚▼澶辫触鍗冲仠姝㈠苟鍗歌浇宸茶锛変笌 `--best-effort`锛堢户缁紝姹囨€婚儴鍒嗗け璐ワ級銆?
- **澶辫触鍗冲仠**锛氭寕鐐逛笉鍙寕鏃朵笉寰椻€滆烦杩囪 hook 缁х画瑁呭叾浠?hook鈥濄€?
- **涓嶅彉閲?*锛氫换浣曢敊璇矾寰勯兘涓嶇暀涓嬪崐涓?hook銆佷笉娈嬬暀 map銆佷笉鏀瑰彉鐩爣琛屼负銆?

## 3. 宸ヤ綔鍖?

### WP1 鎸傜偣鍙鎬ф鏌ヤ笌閿欒鐮侊紙P0锛?

- 鏂板 agent RPC `probe(config, catalog)`锛氫笉鎸傝浇锛屽彧鍋氳В鏋愪笌鏍￠獙锛岃繑鍥?`{ok, bindings, errors[{code,message,hook}]}`锛涗笉鍔犺浇 bridge锛宍E_BRIDGE_ABI` 鐢卞畨瑁呴樁娈佃繑鍥烇紱
- 鏍￠獙椤癸細鏋舵瀯銆乻chema銆佹ā鍧?绗﹀彿/鍋忕Щ銆佸湴鍧€鍙墽琛屻€佸弬鏁?杩斿洖 ABI銆佸姩浣滅洰褰曚笌鍐欏瓧娈点€佽鍒欏瓧鑺傜爜锛堥暱搴?鑼冨洿/姝ユ暟涓婇檺锛夈€乵ap/observer銆乭ook id 涓庨噸澶嶅湴鍧€銆佸凡瀹夎鐘舵€侊紱
- CLI锛歚run.py --check-only`銆乣multiproc.py --check`锛堝彧鎺㈡祴涓嶅畨瑁咃級銆乣--fail-fast/--best-effort`锛?
- 楠屾敹锛氭瀯閫?12 涓け璐ュ満鏅紙缂烘ā鍧椼€佺己绗﹀彿銆佸潖鍋忕Щ銆佸潖 ABI銆佸潖鍔ㄤ綔銆佸潖瑙勫垯銆侀噸澶?hook銆佺己 map銆佸凡瀹夎銆佹潈闄愪笉瓒炽€佺洰鏍囬€€鍑恒€佹灦鏋勪笉绗︼級锛屾瘡涓繑鍥炲敮涓€閿欒鐮佷笖鏃犱换浣曞壇浣滅敤锛涙垚鍔熷満鏅?`--check-only` 閫€鍑虹爜 0銆?

### WP2 ABI 涓庤皟鐢ㄧ害瀹氳ˉ鍏紙P0锛夆€斺€?宸插畬鎴?

- 鏍囬噺锛歚int/uint/int64/uint64/pointer/float/double` 鍙傛暟涓庤繑鍥烇紱鍔ㄤ綔 `return_float` / `return_double`锛汢LOCK 鍔ㄤ綔鍙０鏄?`errno` 骞剁敱鏇挎崲鍥炶皟鍐欏洖璋冪敤鑰咃紱PASS 璺緞 `errno` 閫忎紶锛圠inux 宸查獙璇侊紱Windows 浠嶅彧鏈?`lastError` 璧嬪€艰矾寰勶級銆?
- 缁撴瀯浣撴寜鍊煎弬鏁颁笌 sret锛欶rida 鏃犳硶鐩存帴缂栫粍锛屾敼涓?**鎸夌鍚嶇敓鎴愬師鐢?shim**锛坄runtime/frida/shim.py`锛夛細
  1. bundle 鏋勫缓鏈熸寜 spec 鐢熸垚骞剁紪璇?`__vg_shim_<n>`锛堢湡瀹炵粨鏋勪綋绫诲瀷鏉ヨ嚜鐩爣澶存枃浠?婧愮爜锛夛紱
  2. 瀹夎鏈?agent `Module.load` shim锛宍__vg_shim_bind(program, limit, vg_run)` + `__vg_shim_set_original(target)`锛屽啀 `Interceptor.replace(target, shim_entry)`锛?
  3. shim 鎶婄粨鏋勪綋鍙傛暟鎸夊湴鍧€銆佹爣閲忔寜浣嶅～鍏?6 涓?VM 妲斤紝璋冪敤 VM 鍒ゅ畾锛汢LOCK 鎵ц缂栬瘧鏈熷浐瀹氱殑 `block_c`锛堝闆跺垵濮嬪寲缁撴瀯浣撳悗杩斿洖锛夛紝PASS 璋冪敤鍘熷嚱鏁般€?
  4. manifest 涓?guard 澧炲姞 `shim: {path, entry}`锛沗load_bundle` 瑙ｆ瀽璺緞骞舵牎楠屽彲閫?`sha256`锛沺robe 鏍￠獙 shim 瀛楁涓庘€渟him guard 涓嶆敮鎸?observations鈥濄€?
- 鍙樺弬鍑芥暟锛歚varargs: true` 涓€寰嬫嫆缁濓紙`E_ARITY_UNSUPPORTED`锛夛紝涓嶅仛 ABI 鐚滄祴銆?
- 宸茬煡闄愬埗锛歴him guard 鐩墠涓嶅彂閫?decision 浜嬩欢銆佷笉鏀寔 observers/maps锛堝畨瑁呮湡鎷掔粷锛夛紱shim 妯″潡鏃犳硶鍗歌浇锛團rida 闄愬埗锛夛紝鍗歌浇鍙仮澶嶅師鍑芥暟銆?
- 楠屾敹锛歩nt/int64/pointer/void/float/double 鍙屽悜銆乪rrno 閫忎紶/璁剧疆銆佺粨鏋勪綋鎸夊€?+ sret 鐨?BLOCK/PASS銆佸彉鍙傛嫆缁濓紝鍧囧湪 WSL 瀹炴祴閫氳繃銆?

### WP3 鍔ㄤ綔鐩綍琛ュ叏锛圥0锛夆€斺€?宸插畬鎴?

- 杩斿洖绫伙細`return_int/int64/void/null/string/float/double`锛屽潎鍙檮甯?`errno`銆?
- 杈撳嚭鍙傛暟鍒濆鍖栵細`writes` 鏀寔 pointer 绫诲瀷鍐?`value: 0`锛堢疆 NULL锛夈€乣u32/u64` 鍐?0/甯搁噺锛屽彲鐢ㄤ簬鍒濆鍖栧涓緭鍑哄弬鏁般€?
- 澶氬瓧娈靛啓锛氬悓涓€鍔ㄤ綔鍙０鏄庡涓?`writes`锛屾寜澹版槑椤哄簭鎵ц銆?
- 璧勬簮娓呯悊/缁勫悎鍔ㄤ綔锛氭柊澧?`calls`锛歚[{module, symbol, args: [{arg: i} | {constant: n} | {string: "..."}]}]`锛涘畨瑁呮湡瑙ｆ瀽 module/symbol 骞舵瀯閫?`NativeFunction`锛孊LOCK 鏃跺厛鍐欏瓧娈靛啀璋冪敤锛屾渶鍚庤繑鍥炲姩浣滃€煎苟鍐?errno銆?
- 骞傜瓑锛氬姩浣滃彲澹版槑 `once: true`锛屽壇浣滅敤锛坄calls`锛夋瘡涓?hook 鍙墽琛屼竴娆★紝杩斿洖鍊间粛姣忔閮界敓鏁堬紱瀛楁鍐欏ぉ鐒跺箓绛夈€?
- 鍐欏墠瀹夊叏妫€鏌ワ細杩愯鏈熷姣忎釜 `writes` 妫€鏌ョ洰鏍囨寚閽堥潪绌恒€佸湴鍧€钀藉湪 `w` 鏉冮檺鐨勬槧灏勫唴銆乣offset+width` 涓嶈秺鐣岋紱澶辫触鏃惰烦杩囪鍐欏苟鍙戦€?`action_write_failed:<arg>@<offset>` 璇婃柇锛屼笉宕╂簝銆俙calls` 寮傚父鍙戦€?`action_call_failed` 璇婃柇銆?
- probe 鏍￠獙锛歚calls` 鐨?module/symbol 鍙В鏋愩€佸弬鏁板紩鐢?甯搁噺/瀛楃涓插悎娉曘€乣once` 涓哄竷灏旓紱鍚﹀垯 `E_ACTION_CALL_INVALID` / `E_ACTION_WRITE_INVALID`銆?
- 楠屾敹锛氳緭鍑烘寚閽堢疆 NULL銆佸瀛楁鍐欍€佹竻鐞嗗嚱鏁拌皟鐢ㄣ€乷nce 骞傜瓑銆丯ULL 鐩爣鍐欏け璐ヨ瘖鏂€乸robe 闈炴硶璋冪敤鎷掔粷锛屽潎鍦?WSL 瀹炴祴閫氳繃銆?

### WP4 鐢熸晥鑷瘉锛圥0锛夆€斺€?宸插畬鎴?

- `manifest.smoke` 澹版槑涓€娆¤Е鍙戞柟寮忥細`{"type": "signal", "signal": "SIGUSR1", "hook": "guard_id", "timeout_ms": 2000}`锛屼篃鏀寔 `{"type": "exec", "command": "... {pid} ..."}` 涓?`{"type": "none"}`锛沗run.py`/`multiproc.py` 瀹夎鍚庤嚜鍔ㄨЕ鍙戝苟杞璇?hook 鐨?BLOCK 璁℃暟銆?
- 缁撴灉涓夊垎锛歚installed_verified`锛堣瀵熷埌 BLOCK锛夈€乣installed_unverified`锛堟湭澹版槑 smoke锛宍E_SMOKE_NOT_DECLARED`锛夈€乣failed`锛堝０鏄庝簡浣嗘病瑙傚療鍒?BLOCK锛宍E_SMOKE_FAILED`锛夈€?
- 澶辫触绛栫暐锛氶粯璁ゅ嵏杞藉凡瑁?bundle 骞朵互閫€鍑虹爜 9 缁撴潫锛沗--smoke-warn-only` 淇濈暀瀹夎銆佸彧鍛婅銆?
- agent 鏂板 `stats()` RPC锛屾寜 hook 杩斿洖 `{calls, blocks}`锛沗install` 鍥炴墽涓?`effect` 涓€璧峰啓鍏?JSON 杈撳嚭銆?
- 闄愬埗锛歴him guard 灏氭棤鍐崇瓥璁℃暟锛坰moke 鏃犳硶楠岃瘉 shim 鐩爣锛夛紱`exec` 瑙﹀彂鍛戒护鐢辫ˉ涓佷綔鑰呰礋璐ｅ箓绛変笌瀹夊叏銆?
- 楠屾敹锛歴ignal 瑙﹀彂楠岃瘉 guard銆佹湭澹版槑 smoke 璁?unverified銆丳ASS-only 琛ヤ竵琚垽 failed銆丆LI 涓庡杩涚▼璺緞鍧囪緭鍑?smoke 鐘舵€侊紝鍧囧湪 WSL 瀹炴祴閫氳繃銆?

### WP5 澶氳繘绋嬩笌瑙掕壊锛圥0锛夆€斺€?宸插畬鎴?

- **瑙掕壊鎺ㄦ柇**锛坄classify_roles`锛夛細鍦ㄥ悓涓€鍙墽琛岀殑鍖归厤杩涚▼鏍戦噷锛屾湁瀛愯繘绋嬬殑鏍规槸 master锛屽叾浣欐槸 worker锛沗--helper-arg` 鎸囧畾鐨勫懡浠よ瀛愪覆鎶婅繘绋嬫爣鎴?helper锛涘涓嫭绔?prefork 瀹炰緥鍚勮嚜璇嗗埆鍑?master锛涘崟杩涚▼搴旂敤鏈韩鎸?worker 澶勭悊銆?
- **閫夋嫨**锛歚--role workers|all|master|helpers`锛堥粯璁?`workers`锛夛紱`--pid` 鏄惧紡鎸囧畾鏃朵笉鍋氳鑹茶繃婊ゃ€?
- **spawn 妯″紡**锛氬厛鐢?`--spawn-grace`锛堥粯璁?0.3s锛夌瓑寰?master fork 鍑?worker锛沗--role workers` 鏃惰烦杩?master 浣嗗湪棣栬疆鎵弿鍚庢仮澶嶅畠浠ヤ究 fork锛涜嫢瀹介檺鏈熷唴浠嶆棤瀛愯繘绋嬶紙鍗曡繘绋嬪簲鐢級锛屾妸琚惎鍔ㄨ繘绋嬫寜 worker 瀹夎銆?
- **瀹夎绐楀彛**锛氭瘡娆″畨瑁呰褰?`latency_ms`锛堜粠棣栨鍙戠幇鍒板畨瑁呭畬鎴愶級涓?`window_exceeded`锛沗--max-install-latency-ms` 瓒呰繃闃堝€兼椂缃綅骞跺湪 summary 绱 `late_installs`銆傝繖鏄?*娴嬮噺**锛屼笉鏄€滈璇锋眰鍓嶅畬鎴愨€濈殑纭繚璇併€?
- **閲嶅惎/閲嶆寕**锛氭壂鎻忓惊鐜寔缁畨瑁呮柊鍑虹幇鐨勮繘绋嬶紱`/proc/<pid>/stat` 鐨?starttime 鍙樺寲瑙嗕负 pid 澶嶇敤锛堝彂鍑?`replaced` 浜嬩欢骞堕噸瑁咃級锛涘畨瑁呭け璐ユ寜 `--retry-delay`锛堥粯璁?2s锛変笌 `--max-attempts`锛堥粯璁?3锛夐€€閬块噸璇曘€?
- **鏉冮檺杈圭晫**锛歒ama `ptrace_scope=1` 涓嬪彧鑳芥敞鍏ユ湰杩涚▼锛堟垨 spawn 鏍戯級鐨勫悗浠ｏ紱娉ㄥ叆鏃犲叧杩涚▼闇€瑕?root/CAP_SYS_PTRACE銆?
- 楠屾敹锛歚--role workers` 鍙 3 涓?worker锛坢aster 璺宠繃锛夛紱`--role all` 瑁?1 master + 3 worker锛況espawn 妯″紡涓嬮『搴忓嚭鐜扮殑涓や釜 worker 閮借閲嶆柊瀹夎锛涘欢杩熼槇鍊艰兘鏍囪 `late_installs`銆傚洖褰掕剼鏈細`tests/workloads/userspace/frida/verify_multiproc_roles.sh`銆?
- 闄愬埗锛歨elper 璇嗗埆渚濊禆鍛戒护琛屾爣璁帮紱鈥滈璇锋眰鍓嶁€濆彧娴嬮噺涓嶅己鍒讹紱fork 涓?exec 鐨勫瓙杩涚▼缁ф壙 inline hook 鐨?Frida 闄愬埗浠嶅湪锛堟湰瀹炵幇鍙€愯繘绋嬪畨瑁呮柊杩涚▼锛夈€?

### WP6 绾跨▼涓庡苟鍙戝畨鍏紙P0锛夆€斺€?瀹屾垚锛坧reload 妯″紡锛汧rida attach 璺緞闄愬埗宸叉枃妗ｅ寲锛?

宸插疄鐜板苟楠岃瘉锛?
- **鍗歌浇闈欓粯**锛歚runtime/frida/lifecycle.py` 鍦ㄥ嵏杞芥椂杞 `callbacks active`锛岀瓑鍥炶皟閫€鍑哄悗鍐嶆挙閿€锛沗run.py`/`multiproc.py` 鐨勫嵏杞借矾寰勭粺涓€浣跨敤瀹冦€傚崟鍏冩祴璇曡鐩栭噸璇曘€佽秴鏃躲€佸紓甯镐紶鎾€?
- **绾跨▼浣滅敤鍩熻娴嬶紙Frida attach锛?*锛氳瀵熺偣鍦?pthread 涓婂伐浣滄甯革紱2 绾跨▼ telemetry 娴嬭瘯楠岃瘉鈥滄瘡绾跨▼涓€涓?scope/鍊尖€濄€?
- **澶氱嚎绋嬮棬鎺э紙LD_PRELOAD 妯″紡锛?*锛歚runtime/preload/build.py` 鐢熸垚闈欐€侀摼鎺?`runtime/vm.c` 鐨勫師鐢熷簱锛屽ぉ鐒剁嚎绋嬪畨鍏紱4 绾跨▼ 脳 25 娆¤皟鐢ㄥ叏閮?BLOCK锛汸ASS 缁?`dlsym(RTLD_NEXT)` 璋冨師鍑芥暟锛涘姩浣滃啓/errno 鐢熸晥锛坄tests/test_preload.py`锛?07 passed锛夈€?
- **map 绾跨▼浣滅敤鍩燂紙preload锛?*锛氳瀵?wrapper 涓?guard wrapper 鍏辩敤鍘熺敓 map锛宻cope 鍙?`pthread_self()`锛涘疄娴?thread-scoped map 涓嬫瘡绾跨▼鐙珛鍊硷細2 绾跨▼瓒呴檺琚?BLOCK銆? 绾跨▼鏀捐锛坄checked_ok=50, checked_blocked=50`锛実lobal 璇箟涓嬩細涓嶅悓锛夈€?
- **閲嶅叆淇濇姢**锛歱reload 妯″紡涓嬮€掑綊璋冪敤缁?wrapper鈫抮eal鈫掗€掑綊 PLT 鍥炲埌 wrapper锛宍PASS` 瑙勫垯涓嬮€掑綊缁撴灉姝ｇ‘锛坄preload_recurse(4)=4`锛屾棤宕╂簝锛夛紱Frida JS 璺緞淇濈暀姣忕嚎绋嬮噸鍏ユ繁搴﹀疄鐜帮紝浣嗗彈 replace 鍥炶皟闄愬埗鏈仛閫掑綊鍘嬫祴銆?

Frida attach 璺緞闄愬埗锛堣瑙?`docs/ai/FRIDA_THREAD_SAFETY.md`锛夛細
- 闈炰富绾跨▼鐨?replace 鍥炶皟鎵ц绋嶅鏉?JS/VM 浼氬穿婧冩垨鎸傝捣锛涘師鐢?shim锛堝惈闈欐€侀摼鎺?VM锛夊悓鏍锋寕璧枫€?
- 鍥犳 **Frida attach 妯″紡浠呮敮鎸佷富绾跨▼/鍗曠嚎绋嬬洰鏍?*锛涘绾跨▼鐩爣浣跨敤 LD_PRELOAD 妯″紡銆?
- preload 妯″紡鍙鐩栫粡杩囧姩鎬佺鍙疯〃锛圥LT锛夌殑璋冪敤锛涜瀵?map 鏀寔绠€鍗?`key_arg`/`value_arg`锛堟棤 selector锛夛紱闈欐€侀摼鎺ョ洰鏍囦笉閫傜敤銆?

### WP7 鐢熷懡鍛ㄦ湡涓庡け璐ュ畨鍏紙P1锛夆€斺€?宸插畬鎴?

- **杩涚▼鍐呭師瀛愬洖婊?*锛歛gent 鍏堣В鏋愬叏閮?guards/observers/鍔ㄤ綔/瑙勫垯锛屽啀缁熶竴鏇挎崲锛涗换涓€姝ュけ璐?`remove()` 鎾ら攢宸茶 hooks銆傛祴璇曪細涓や釜 guard 涓浜屼釜缂哄姩浣?鈫?瀹夎澶辫触銆乣status.installed=false`銆佸師鍑芥暟琛屼负涓嶅彉銆侀殢鍚庡彲姝ｅ父瀹夎銆?
- **鍗歌浇 barrier**锛歚lifecycle.uninstall` 杞 `callbacks active`锛岃秴鏃剁敱 `--uninstall-timeout-ms`锛堥粯璁?2000ms锛夋帶鍒讹紱鍗曟祴瑕嗙洊閲嶈瘯銆佽秴鏃朵笌鏃犲叧寮傚父浼犳挱銆?
- **宕╂簝闅旂**锛氬杩涚▼ launcher 涓潃鎺変竴涓?worker锛屼粎璇?pid 鎶?`detached`锛屽叾浣?worker 缁х画浜х敓 BLOCK锛泂ummary 鏃?failures銆傚洖褰掕剼鏈?`verify_lifecycle.sh`銆?
- **fail-fast 鍥炴粴**锛歚--fail-fast` 鍦ㄩ娆″畨瑁呭け璐ユ椂涓骞跺嵏杞藉叏閮ㄥ凡瑁呰繘绋嬶紝閫€鍑虹爜 4锛涘洖褰掕剼鏈獙璇?`installed=0` 涓?summary `fatal` 闈炵┖銆?
- **鐩爣琚浛鎹?*锛歚same_image()` 鍚屾椂姣旇緝 starttime 涓?exe 鐪熷疄璺緞锛涗笉涓€鑷村彂 `replaced` 骞堕噸瑁咃紙exec 鍚?session 鏂紑涔熶細瑙﹀彂閲嶈锛夈€傚崟娴嬭鐩?pid 澶嶇敤/鎹㈤暅鍍忥紱WP5 respawn 闆嗘垚娴嬭瘯瑕嗙洊椤哄簭鏂拌繘绋嬨€?
- 楠屾敹锛氫笂杩版祴璇曚笌鍥炲綊鑴氭湰鍦?WSL 瀹炴祴閫氳繃銆?

### WP8 瑙傛祴涓庤繍缁达紙P1锛夆€斺€?宸插畬鎴?

- `runtime/frida/metrics.py`锛歚EventStream` 鎶婄粺涓€浜嬩欢鍐欐垚甯?`ts` 鐨?JSONL锛沗MetricsCollector` 缁熻 decisions/passes/blocks/observations/diagnostics/reentries锛屽苟鍦?*婊戝姩绐楀彛**鍐呰瘖鏂暟瓒呴槇鍊兼椂鎵撳紑鐔旀柇銆?
- `run.py` / `multiproc.py` 鏂板锛歚--events PATH`锛堢粺涓€浜嬩欢娴侊級銆乣--metrics-interval`锛堝懆鏈?metrics 浜嬩欢锛夈€乣--circuit-max-diagnostics`/`--circuit-window-ms`/`--no-circuit-breaker`銆?
- 鐔旀柇琛屼负锛氬懡涓槇鍊?鈫?鍙戦€?`circuit-open` 鈫?瀵?*璇ヨ繘绋?*鍗歌浇锛坄circuit-uninstalled`锛夆啋 璁?`E_CIRCUIT_OPEN`銆佷笉鍐嶉噸璇曪紱launcher 姹囨€诲寘鍚?`circuits` 涓?`metrics`锛岄€€鍑虹爜 **10**锛坄EXIT_CIRCUIT`锛夈€?
- 楠屾敹锛氬崟娴嬭鐩栬鏁?绐楀彛杩囨湡/闃堝€?浜嬩欢娴佹椂闂存埑锛沴ive 娴嬭瘯鐢ㄥ閲?1 鐨勮娴?map 鍒堕€?`observation_map_full` 骞惰Е鍙戠啍鏂紱CLI 绔埌绔獙璇?`run.py --circuit-max-diagnostics 1` 閫€鍑?10 骞跺啓鍑轰簨浠舵祦锛宍multiproc.py` 鍚屾牱閫€鍑?10 涓?summary 甯?`circuits`銆?
- 闄愬埗锛氱啍鏂寜杩涚▼鐙珛锛涜瘖鏂潵婧愪负 agent telemetry锛坉ecision 鐨?diagnostic 涓?diagnostic 浜嬩欢锛夛紝shim guard 鏆傛棤 decision 浜嬩欢銆?

### WP9 骞冲彴涓庤鐩栬竟鐣岋紙P1锛夆€斺€?宸插畬鎴愶紙鏂囨。 + 鍋忕Щ琛ㄥ伐鍏凤級

- 鏀寔鐭╅樀銆佹潈闄愭ā鍨嬩笌浜や粯鏂瑰紡鍐欏叆 `docs/ai/PLATFORM_AND_LIMITS.md`銆?
- 鏂板 `runtime/frida/symbols.py`锛氫粠 ELF64 瑙ｆ瀽 PT_LOAD 鍩哄潃 + `nm` 绗﹀彿锛岀敓鎴?`{build_id, load_bias, symbols}` 鍋忕Щ琛紱瀹炴祴瀵?`frida_fixture` 鐢熸垚琛ㄥ悗鐢?`offset` 鎸傜偣瀹夎骞舵垚鍔?BLOCK銆?
- 璇█杈圭晫锛欳/C++ 鏀寔锛汫o/Rust 浠呭亸绉荤骇涓斿姩浣滃彈闄愶紱Java/JS/JIT 涓嶆敮鎸併€?
- 鏄庣‘鏈疄鐜帮細ARM64锛堜粎 x86-64锛夈€侀潤鎬?musl 瀹炴祴銆佸绾跨▼闂ㄦ帶锛堣 WP6锛夈€?

### WP10 浜や粯涓庨泦鎴愶紙P2锛夆€斺€?宸插畬鎴?

- **bundle 韬唤**锛歚runtime/frida/bundle.py` 鎻愪緵绋冲畾 digest锛坢anifest/catalog/瑙勫垯/bridge/shim锛夈€乣bundle_version` 鏍￠獙涓?HMAC-SHA256 绛惧悕锛沗load_bundle` 鍦?`VULGATE_BUNDLE_KEY` 璁剧疆鏃跺己鍒堕獙绛撅紝`bundle_digest` 鍐欏叆瀹夎鍥炴墽銆佷簨浠朵笌 summary锛涘崟娴嬭鐩栫ǔ瀹?绡℃敼/缂哄け绛惧悕/鐗堟湰鎷掔粷銆?
- **鎺у埗閫氶亾**锛歚runtime/frida/control.py`锛圲nix socket锛? `run.py`/`multiproc.py --control-socket`锛沗cli.py status/metrics/uninstall --socket` 鍙杩愯涓殑 launcher 鏌ヨ涓庡嵏杞斤紱闆嗘垚娴嬭瘯楠岃瘉 status/metrics/CLI metrics/uninstall銆?
- **CLI**锛歚cli.py check --pid` 涓€娆℃€у彲琛屾€ф鏌ワ紱闀块┗瀹夎鐢?`run.py`/`multiproc.py` 瀹屾垚锛團rida hook 灞炰簬浼氳瘽锛孋LI 杩涚▼閫€鍑哄嵆鎾ら攢锛夈€?
- **鏉冮檺鎸囧崡/systemd/瀹瑰櫒**锛歚PLATFORM_AND_LIMITS.md` + `deploy/README.md` + `deploy/vulgate-frida.service`锛堜粎 `CAP_SYS_PTRACE`銆乣NoNewPrivileges`銆佹帶鍒?socket 涓庝簨浠舵棩蹇楋級銆?
- 闄愬埗锛氱鍚嶄负鍏变韩瀵嗛挜 HMAC锛堥潪瀵圭О绛惧悕鏈仛锛夛紱鏈湪鐪熷疄 nginx/httpd/PHP 浜岃繘鍒朵笂鎵ц WP9/WP10 娴佺▼锛坴1 鏃?benchmark 鏋勫缓锛夈€?

## 3.0 琛ヤ竵 DSL 灞傦紙`runtime/dsl`锛?

闈㈠悜鈥滆緭鍏ヨˉ涓?鈫?鎸傝浇杩愯鈥濈殑澹版槑寮忓墠绔細

- DSL 鏍煎紡锛歚鎸傝浇鐐筦锛坄浣嶇疆` / `鎬ц川` / `琛屼负`锛? `鍔ㄤ綔`锛?
- 缂栬瘧鍣ㄦ妸琛屼负缂栬瘧鎴?Frida `NativeCallback` agent锛孭ASS 鐢?`SystemFunction` 璋冨師鍑芥暟锛?
  BLOCK 鎵ц鍔ㄤ綔锛?
- 20 涓?CVE 鐨?DSL 浣嶄簬 `runtime/dsl/patches/*.vg`锛岀敱 `runtime/dsl/generate20.py`
  浠?`build/declarative20-specs` 鐢熸垚锛?
- 楠岃瘉锛歚runtime/dsl/validate20.py` 鐢ㄥ悎鎴?fixture 楠岃瘉 BLOCK/PASS/鐪熷疄鍐呭瓨璇诲彇锛?
  鏈嶅姟鍣ㄥ疄娴?**24/24 鍦烘櫙閫氳繃**锛?
- 闄愬埗锛欶rida 鍗曠嚎绋嬭矾寰勩€佺粨鏋勪綋杩斿洖/鍔ㄤ綔 writes/鐪熷疄 callsite 鏈帴鍏ワ紝璇﹁
  `runtime/dsl/README.md`銆?

## 3.1 鍘熺敓鍚庣锛坆undle 椹卞姩锛孎rida Python 娉ㄥ叆锛?

`runtime/native/` 鎻愪緵涓や釜浠庣幇鏈?bundle/action catalog 鐢熸垚鐨勫師鐢熷悗绔細

- **plthook**锛堥粯璁わ級锛欸OT/PLT 鏇挎崲锛屾敮鎸?BLOCK + PASS锛坄dlsym` 璋冨師鍑芥暟锛夛紱鍗曟 live PASS **20/20**銆?
  BLOCK/PASS 鍚?5 杩涚▼鍥炲綊閫氳繃锛涘彧瑕嗙洊 PLT 璋冪敤銆?
- **inline**锛坒unchook + 淇″彿 STW锛夛細鏀寔 symbol/offset 鎸傜偣锛孊LOCK-only锛堣姹?`always_block: true`锛夛紱
  BLOCK 鍗曟 live + 5 杩涚▼鍥炲綊閫氳繃锛涘悓涓€ bundle 璇箟锛坢anifest/actions/rule/step_limit/return/writes/errno锛夈€?
- `runtime/native/build.py` 鐢熸垚 agent锛沗runtime/native/run.py` 鐢?Frida Python 娉ㄥ叆骞惰緭鍑?
  `probe_code/install_code/uninstall_code/status` 鍥炴墽锛涢敊璇爜 10鈥?2銆?
- 闄愬埗锛歩nline PASS 涓嶇ǔ瀹氾紙funchook trampoline锛夛紝PASS 鍦烘櫙璧?plthook锛沷bservers/maps銆乻moke銆乵etrics 鏈帴鍏ワ紱
  鏈獙璇?ARM64/Windows銆?

## 4. 閲岀▼纰?

| 閲岀▼纰?| 鍐呭 | 楠屾敹 |
|---|---|---|
| M1 鍙寕涓斿彲瑙ｉ噴 | WP1 + WP3 鍩虹 | 12 涓敊璇満鏅敊璇爜姝ｇ‘锛涙垚鍔熷満鏅?`check` 閫氳繃 |
| M2 瑁呭緱涓婁笖璇佹槑鐢熸晥 | WP2 + WP4 | 鍥涚被绛惧悕 + 鍔ㄤ綔 + smoke 鍏ㄩ儴閫氳繃 |
| M3 鐢熶骇褰㈡€?| WP5 + WP6 + WP7 | fork 鍨?4 worker 鍏ㄨ锛涘绾跨▼鍘嬫祴閫氳繃锛涘嵏杞?鍥炴粴閫氳繃 |
| M4 鍙繍缁?| WP8 + WP10 | 鎸囨爣/鐔旀柇/绛惧悕/鏉冮檺鏂囨。榻愬 |

## 5. 娴嬭瘯鐭╅樀

- 鍚堟垚绋嬪簭锛氬崟杩涚▼銆乫ork+exec銆乫ork 涓?exec锛坢aster/worker锛夈€佸绾跨▼銆佺儹鎸傘€侀噸鍚€佸穿婧冿紱
- 鐪熷疄鐩爣锛歯ginx/httpd/PHP锛堥渶鍦?v1 閲嶅缓 `build/benchmark20` 浜岃繘鍒讹級锛?
- 閿欒娉ㄥ叆锛氱己妯″潡/缂虹鍙?鍧忓亸绉?鍧?ABI/鍧忓姩浣?鍧忚鍒?閲嶅 hook/缂?map/鏉冮檺鎷掔粷/鐩爣閫€鍑?鏋舵瀯涓嶇/宸插畨瑁咃紱
- 闀跨ǔ锛氳繛缁畨瑁?鍗歌浇 1000 娆★紱24 h 杩愯鏃犲彞鏌?鍐呭瓨澧為暱銆?

## 6. 褰撳墠瀹炵幇鏄犲皠

| 宸ヤ綔鍖?| 鐜扮姸 |
|---|---|
| WP1 | 閮ㄥ垎锛歛gent 瀹夎鍓嶄細鏁翠綋瑙ｆ瀽骞舵嫆缁濓紙宸叉湁鍘熷瓙鎬э級锛屼絾鏃?`probe` RPC銆佹棤閿欒鐮佷綋绯汇€佹棤 `--check-only` |
| WP2 | 瀹屾垚锛氭爣閲?float/double銆乪rrno銆佺粨鏋勪綋鎸夊€?sret锛堝師鐢?shim锛夈€佸彉鍙傛嫆缁濓紱shim guard 涓嶆敮鎸?observers/maps 涓?decision 浜嬩欢锛堝畨瑁呮湡闄愬埗锛?|
| WP3 | 瀹屾垚锛氬瀛楁鍐欍€佽緭鍑哄弬鏁板垵濮嬪寲銆乣calls` 娓呯悊/缁勫悎鍔ㄤ綔銆乣once` 骞傜瓑銆佸啓鍓嶈寖鍥存鏌ヤ笌璇婃柇銆乸robe 鏍￠獙 |
| WP4 | 瀹屾垚锛歮anifest `smoke`锛坰ignal/exec/none锛夈€佸畨瑁呭悗鑷姩瑙﹀彂銆乣stats()` 璁℃暟銆乣installed_verified`/`installed_unverified`/`failed`銆佸け璐ュ嵏杞戒笌 `--smoke-warn-only` |
| WP5 | 瀹屾垚锛氳鑹叉帹鏂笌 `--role`銆乻pawn 瀹介檺涓?master 璺宠繃銆佸畨瑁呭欢杩熸祴閲忋€佸け璐ラ€€閬块噸璇曘€乻tarttime pid 澶嶇敤妫€娴嬨€侀噸鍚噸鎸傦紱鍥炲綊鑴氭湰宸叉彁浜?|
| WP6 | 瀹屾垚锛坧reload 妯″紡锛夛細鍗歌浇闈欓粯銆佸绾跨▼ BLOCK銆佺嚎绋嬩綔鐢ㄥ煙 map锛?0/50 瀹炴祴锛夈€侀€掑綊 PASS锛汧rida attach 璺緞浠呭崟绾跨▼/涓荤嚎绋嬶紝闄愬埗宸叉枃妗ｅ寲 |
| WP7 | 瀹屾垚锛氳繘绋嬪唴鍘熷瓙鍥炴粴銆佸嵏杞?barrier/瓒呮椂銆佸穿婧冮殧绂汇€乫ail-fast 鍥炴粴銆乻tarttime+exe 鐨勬浛鎹㈡娴嬶紱鍥炲綊鑴氭湰宸叉彁浜?|
| WP8 | 瀹屾垚锛氱粺涓€浜嬩欢娴併€佹瘡杩涚▼ metrics銆佹粦鍔ㄧ獥鍙ｇ啍鏂笌鑷姩鍗歌浇銆侀€€鍑虹爜 10锛涘崟娴嬩笌 CLI 绔埌绔獙璇?|
| WP9 | 瀹屾垚锛堟枃妗?+ 鍋忕Щ琛ㄥ伐鍏凤級锛歺86-64 瀹炴祴锛泂tripped 鍋忕Щ琛ㄥ疄娴嬶紱ARM64/闈欐€侀摼鎺?澶氱嚎绋嬫槑纭垪涓烘湭鏀寔 |
| WP10 | 瀹屾垚锛歜undle digest/鐗堟湰/绛惧悕銆佹帶鍒?socket + CLI銆佹潈闄?systemd/瀹瑰櫒鏂囨。锛涚鍚嶄负 HMAC 鍏变韩瀵嗛挜 |

## 7. 寤鸿鎵ц椤哄簭

1. **WP1**锛堥敊璇爜 + probe + `--check-only`锛夛細鍚庣画涓€鍒囧伐浣滅殑鍦板熀锛屼笖鐩存帴瀵瑰簲鐢ㄦ埛瑕佹眰鈥滀笉鑳芥寕灏辫繑鍥為敊璇爜骞跺仠姝⑩€濄€?
2. **WP2 + WP3 + WP4**锛圓BI/鍔ㄤ綔/鑷瘉锛夛細鍐冲畾鈥滆浜嗘槸鍚︾湡鐨勭敓鏁堚€濄€?
3. **WP5**锛堣鑹?+ 棣栬姹傜獥鍙ｏ級锛氬喅瀹氱湡瀹炴湇鍔″舰鎬佸彲鐢ㄣ€?
4. **WP6 + WP7**锛堝苟鍙?鐢熷懡鍛ㄦ湡锛夛細鍐冲畾绋冲畾鎬с€?
5. **WP8 + WP10**锛堣繍缁?浜や粯锛夛細鍐冲畾鍙氦浠樸€?



