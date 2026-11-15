# VulGate Patch DSL

`runtime/dsl/` 鏄ˉ涓?DSL 鐨勭紪璇?瑙ｉ噴灞傦細鎶娾€滄寕杞界偣 + 琛屼负鈥濈殑琛ヤ竵鎻忚堪缂栬瘧鎴?
Frida agent锛坄NativeCallback` + `SystemFunction`锛夛紝鍦ㄧ洰鏍囪繘绋嬮噷瀹夎骞舵墽琛屻€?

## DSL 璇硶锛堣嫳鏂囧叧閿瓧锛?

```text
action NGX_ERROR_RETURN:
{
    return_type: int
    return: -1
}

mount CVE-2026-97205:
{
    location: symbol="ngx_http_copy_filter", args=[pointer, pointer], return=int64
    nature: intercept
    behavior:
    {
        value["counter"] = vg_read_u32(vg_read_pointer(arg0 + 1000) + 1181);
        if ((value["counter"] & 255) >= 250) {
            return block("NGX_ERROR_RETURN");
        }
    }
}
```

- `mount <id>:`锛氫竴涓寕杞界偣锛?
- `location`锛歚module`锛堝彲閫夛級銆乣symbol`銆乣offset`锛堟湰鍦扮鍙凤級銆乣args`銆乣return`锛?
- `nature`锛歚read_point` 鎴?`intercept`锛?
- `behavior`锛欳 椋庢牸璇彞銆俙value["x"] = ...` 鍐欏叆瑙傚療鍊硷紝鍚庣画鍙洿鎺ヨ `value["x"]`锛?
  `return block("ACTION");` 琛ㄧず BLOCK锛涗笉鍐?return 鍒欒惤鍒?PASS锛岃皟鐢ㄥ師鍑芥暟锛?
- `action <id>:`锛欱LOCK 杩斿洖鍔ㄤ綔锛沗return_type`/`return`/鍙€?`errno`銆?

鏃х殑涓枃鍏抽敭瀛楋紙`鍔ㄤ綔/鎸傝浇鐐?浣嶇疆/鎬ц川/琛屼负/璇诲彇鐐?鎷︽埅鐐?鍙傛暟/杩斿洖绫诲瀷/杩斿洖`锛変粛琚В鏋愬櫒鎺ュ彈锛?
浣嗙敓鎴愬櫒鍜屼粨搴撳唴 20 涓ˉ涓佺粺涓€浣跨敤鑻辨枃銆?

## 缂栬瘧瀹炵幇

1. `parser.py`锛氭壂鎻?`action`/`mount` 椤跺眰鍧楋紝鎸夎姳鎷彿閰嶅钩鎻愬彇 `behavior`锛?
   瑙ｆ瀽 `location` 鐨?`module/symbol/offset/args/return` 鍜屽姩浣滃瓧娈碉紱
2. `compiler.py` 鎶婃瘡涓?mount 缂栬瘧鎴愪竴涓?Frida agent 鐗囨锛?
   - 姣忎釜 `value["x"] = <expr>` 鍙樻垚 `value["x"] = vg_sel("x", () => (<expr>))`
     锛堢敓浜фā寮忔墽琛岀湡瀹炲唴瀛樿鍙栵紱楠岃瘉妯″紡鍙敞鍏?selector 鍊硷級锛?
   - `return block("ACTION")` 鍙樻垚 `return vg_block("ACTION")`锛?
   - C 椋庢牸涓存椂鍙橀噺/`for` 澹版槑杞垚 JS `let`锛?
   - 鍔ㄤ綔琛ㄧ紪璇戜负 JS 瀵硅薄锛宍vg_block` 鎸夎繑鍥炵被鍨嬬敓鎴愯繑鍥炲€?`errno`锛?
   - 姣忎釜 mount 鐢熸垚锛?
     - `new SystemFunction(target, return_type, args)` 淇濆瓨鍘熷嚱鏁帮紱
     - `new NativeCallback(function(arg0...) { ...; return original(...); }, ...)`锛?
     - `Interceptor.replace(target, callback)` 瀹夎锛?
   - 鏀寔 `offset`锛歚module.base.add(offset)` 瑙ｆ瀽鏈湴绗﹀彿锛?
3. `run.py`锛欶rida Python 璇诲彇 DSL 鈫?鑷姩琛?offset 鈫?缂栬瘧 鈫?attach/spawn 鈫?瀹夎锛?
   `resolve.py`锛氳 `/proc/<pid>/maps`锛岀敤 `nm` 绗﹀彿琛ㄤ负鏈湴绗﹀彿鑷姩璁＄畻
   `module.base + offset`锛?
   `validate20.py`锛氬悎鎴?fixture 楠岃瘉 BLOCK/PASS/memory 鍦烘櫙銆?

## 缂栬瘧/瀹夎

```sh
# 鍙紪璇戞鏌?
python -m runtime.dsl.run --dsl runtime/dsl/patches/CVE-2026-97205.vg --check

# spawn 鐩爣骞跺畨瑁?
python -m runtime.dsl.run --dsl runtime/dsl/patches/CVE-2026-97205.vg \
    --spawn ./target --duration 5

# 宸叉湁杩涚▼
python -m runtime.dsl.run --dsl runtime/dsl/patches/CVE-2026-97205.vg \
    --pid 1234 --duration 5
```

## 20 涓?CVE 鐨?DSL

`runtime/dsl/patches/*.vg` 鐢?`build/declarative20-specs` 鐨?
`patch.yaml + app_profile` 鐢熸垚锛?

```sh
python -m runtime.dsl.generate20 --out runtime/dsl/patches
```

鐢熸垚鍣ㄩ渶瑕?`PyYAML`锛坄requirements-dsl.txt`锛夈€?

## 楠岃瘉

```sh
python -m runtime.dsl.validate20 --json /tmp/dsl20.json
```

楠岃瘉鍣ㄤ负姣忎釜 DSL 鐢熸垚涓€涓皬鍨?fixture 鍙墽琛屾枃浠讹紙瀵煎嚭鐩爣绗﹀彿銆佺粺璁″嚱鏁颁綋鎵ц娆℃暟锛夛紝
鐢?Frida 瀹夎 DSL agent锛岀劧鍚庤皟鐢ㄧ洰鏍囷細

- **BLOCK**锛歚body_calls == 0`锛岃繑鍥炲姩浣滃€硷紱
- **PASS**锛氭潯浠朵笉鎴愮珛鏃?`body_calls > 0`锛岃繑鍥炲師鍑芥暟缁撴灉锛?
- **memory 妯″紡**锛氫笉娉ㄥ叆 selector 鍊硷紝鐪熷疄鎵ц鍐呭瓨璇诲彇锛堝綋鍓嶅 `CVE-2026-93479` 璺戦€氾級銆?

鏈嶅姟鍣?test-host 瀹炴祴锛?026-11-16锛夛細

```
28/28 DSL scenarios passed (block + pass)
```

鍏朵腑 20 涓?CVE 鍏ㄩ儴 BLOCK 閫氳繃锛? 涓潯浠跺紡琛ヤ竵棰濆楠岃瘉 PASS锛?
`CVE-2026-109618`锛堝叏灞€绗﹀彿锛夈€乣CVE-2026-47360`锛堟寚閽堝瓧娈碉級棰濆浠?memory 妯″紡楠岃瘉鐪熷疄鍐呭瓨璇诲彇銆?
`CVE-2026-93479`/`42945`/`9256` 宸叉敼涓?return-only 鎸傝浇锛堣
`docs/ai/DSL_RETURN_ONLY_ANALYSIS.md`锛夈€?

## 鏀寔鐨勮〃杈惧紡涓庡姩浣?

- 琛ㄨ揪寮忥細`== != < <= > >=`銆乣&& || !`銆乣+ - *`銆乣& | ^ << >>`銆佹嫭鍙枫€佸父閲忥紱
- 鍐呭瓨璇诲彇锛歚vg_read_u8/u16/u32/u64`銆乣vg_read_s8/...`銆乣vg_read_pointer`锛?
- 鍏ㄥ眬绗﹀彿锛歚global("name")`锛?
- 琛屼负閲屽彲鍐欎复鏃跺彉閲忥紙缂栬瘧涓?JS `let`锛夈€乣if`銆佹湁鐣?`for`锛?
- 鍔ㄤ綔锛歚return_int/int64/void/null/string/float/double`锛沗errno` 鍙€夈€?

## 闄愬埗锛堝綋鍓嶇増鏈級

- 鐢熸垚鐨勬槸 **Frida NativeCallback**锛屼笌 Frida 鍚庣涓€鏍峰彧閫傜敤浜?*鍗曠嚎绋?涓荤嚎绋嬩覆琛岃皟鐢ㄨ矾寰?*锛?
- 缁撴瀯浣?by-value/sret 杩斿洖鏆備笉鏀寔锛?
- `vg_map_get`/`vg_map_present` 鐩墠鏄崰浣嶅疄鐜帮紙brotli 瑙傚療鐐圭殑鐪熷疄 callsite 璇箟鏈帴鍏ワ級锛?
- 鍔ㄤ綔鐨?`writes` 灏氭湭鍦?DSL 缂栬瘧鍣ㄤ腑鎵ц锛涘綋鍓嶉獙璇佷互杩斿洖鍊?鍑芥暟浣撴槸鍚︽墽琛屼负鍑嗭紱
- 2 渚嬩互 memory 妯″紡楠岃瘉锛坄CVE-2026-109618`/`CVE-2026-47360`锛夛紱
  鍏朵綑 18 渚嬮€氳繃 `vg_sel` 娉ㄥ叆 selector 鍊奸獙璇佽涓哄垎鏀紝缂栬瘧浜х墿涓殑鍐呭瓨璇诲彇浠ｇ爜鏈湪鐪熷疄搴旂敤涓婃墽琛岋紱
- 鏈帴鍏?`runtime/frida` 鐨?bundle/smoke/metrics/澶氳繘绋嬶紱杩欐槸鐙珛鐨?DSL 鈫?Frida 瀹夎璺緞銆?

## 鍙傝€?

- Frida `NativeCallback` / `SystemFunction`锛坔ook 鍥炶皟涓庡師鍑芥暟璋冪敤锛夛紱
- 鍘?VulGate 璇箟锛氳鍒欒繑鍥?PASS/BLOCK锛屽姩浣滅洰褰曪紝`value` 瑙傚療妲戒綅锛?
- selector 鍋忕Щ璇箟娌跨敤 `build/declarative20-specs` 鐨?app profile layout銆?

