# Return-only 鍙揪鎬у垎鏋愶紙20 涓?DSL 琛ヤ竵锛?
鏃ユ湡锛?026-11-16  
鐩爣锛氬闇€瑕?action writes 鐨勮ˉ涓侊紝鍒ゆ柇鑳藉惁鏀规寕鍒扳€滆繑鍥炲€艰璋冪敤鑰呮鏌モ€濈殑闈?void 鍑芥暟锛?鐢ㄧ函 return 瀹炵幇 BLOCK锛涗笉鑳借浆鎹㈢殑浠庝氦浠橀泦涓幓鎺夈€?
## 缁撹

- 17/20 鐨?action 鏈潵灏辨病鏈?`writes`锛屽凡缁忔槸 return-only锛?- 3/20 闇€瑕?action writes锛歚CVE-2026-93479`銆乣CVE-2026-42945`銆乣CVE-2026-9256`锛?- 杩?3 涓兘鎵惧埌浜嗗彲鐢ㄧ殑 return-only 鎸傝浇鐐癸紝**鏃犻渶鍒犻櫎浠讳綍婕忔礊**锛?- 浠ｄ环鏄寕杞借寖鍥存瘮鍘熻ˉ涓佹洿瀹斤紙璇箟婕傜Щ锛夛紝闇€鍦ㄦ枃妗ｄ腑鏍囨敞銆?
## 涓変釜鍐欎緷璧栬ˉ涓佺殑杞崲

| CVE | 鍘熸寕杞?| 鍘熷姩浣?writes | return-only 鎸傝浇 | 杩斿洖 | 鐪熷疄 nginx 瀹炴祴 |
|---|---|---|---|---|---|
| CVE-2026-93479 | `ngx_http_script_check_length` | `engine->ip`銆乣engine->status=500` | `ngx_http_script_run` | `NULL` | baseline 200 鈫?patched **500**锛宧it 1 |
| CVE-2026-42945 | `ngx_http_script_regex_start_code`锛坴oid锛?| `engine->ip`銆乣engine->status=500` | `ngx_http_rewrite_handler` | `500` | baseline 302 鈫?patched **500**锛宧it 1 |
| CVE-2026-9256 | 鍚屼笂锛坴oid锛?| 鍚屼笂 | `ngx_http_rewrite_handler` | `500` | 涓?42945 鍏辩敤妯℃澘锛涘悓鍑芥暟鍚屽姩浣?|

杞崲鍚庣殑 DSL 浣嶄簬锛?
- `runtime/dsl/patches/CVE-2026-93479.vg`
- `runtime/dsl/patches/CVE-2026-42945.vg`
- `runtime/dsl/patches/CVE-2026-9256.vg`

## 鍏朵綑 17 涓?
杩欎簺 action 鍙湁杩斿洖鍊?errno锛屾病鏈?writes锛屾湰鏉ュ氨鏄?return-only锛?
```
109618, 109619, 111497, 15176, 27654, 42055(x2), 42533, 47360,
56153, 56154, 56449, 57941, 60005, 63292, 63686, 93546, 97205
```

娉ㄦ剰锛歳eturn-only 鍙繚璇佲€滆ˉ涓佸姩浣滃彲浠ヨ琛ㄨ揪鈥濓紝涓嶄唬琛ㄦ瘡涓兘鍦ㄧ湡瀹炲簲鐢ㄤ笂浜х敓浜嗛鏈?HTTP 鏁堟灉锛?渚嬪 `42533` 杩斿洖 -1 鍚庣湡瀹炲搷搴旀槸 200 绌猴紝娌℃湁鏄庣‘閿欒鐘舵€侊紝闇€瑕佸崟鐙仛璺緞璇箟楠岃瘉銆?
## 杞崲鍒ゆ嵁

涓€涓啓渚濊禆琛ヤ竵鍙互鏀规垚 return-only锛屽綋涓斾粎褰擄細

1. 璋冪敤閾句笂瀛樺湪闈?void 鍑芥暟锛?2. 璇ュ嚱鏁扮殑杩斿洖鍊艰璋冪敤鑰呮鏌ュ苟鐢ㄤ簬涓/閿欒浼犳挱锛?3. 闃诲鑼冨洿鎵╁ぇ鍙帴鍙楋紱
4. 璋冪敤鑰呬笉浼氳鍙栨湭鍒濆鍖?鏃х姸鎬佸鑷村穿婧冦€?
`CVE-2026-42945/9256` 鍘熺洰鏍囨槸 `void`锛屼笉鑳藉湪鍘熸寕杞界偣 return-only锛涙敼鐢?`ngx_http_rewrite_handler`锛堣繑鍥?`ngx_int_t`锛岃繑鍥?500 浼氳 nginx 鐩存帴缁撴潫璇锋眰锛夈€?
## 楠岃瘉

鏈嶅姟鍣?`test-host`锛?
- 鍚堟垚 fixture锛?*28/28 鍦烘櫙閫氳繃**锛?0 BLOCK + 6 PASS + 2 memory锛夛紱
- 鐪熷疄 nginx 1.31.6锛?  - `CVE-2026-93479`锛歚/dynamic/file.txt?dir=www` 200 鈫?500锛宧it 1锛?  - `CVE-2026-42945`锛歚/rewrite/ordinary` 302 鈫?500锛宧it 1锛?- `CVE-2026-27654`锛氭鍓嶅凡瀹炴祴 DAV COPY 204 鈫?405銆?
## 宸茬煡闄愬埗

- return-only 鐗堟湰鏀瑰彉浜嗘寕杞界偣锛屽彲鑳芥嫤鎴瘮鍘熸紡娲炴洿澶х殑鑼冨洿锛?- 鏉′欢琛ヤ竵鐨?selector 閫昏緫琚浛鎹负鏃犳潯浠舵嫤鎴紙93479/42945/9256 鐨勮浆鎹㈢増鏈兘鏄?`if (true)`锛夛紱
- 鐪熷疄搴旂敤瑕嗙洊浠嶅彧楠岃瘉浜?nginx 鐨?3 涓姹傝矾寰勶紱httpd/PHP/Brotli 鏈仛鐪熷疄閲嶆斁銆?
