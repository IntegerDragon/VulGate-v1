# DSL 鐪熷疄搴旂敤閲嶆斁璁板綍锛坬izhi-51锛?
鏃ユ湡锛?026-11-16  
鐜锛歲izhi-51锛孶buntu 24.04锛孭ython 3.12 venv锛孎rida 17.26.2銆?
## 鐩爣

鐢?`runtime/dsl` 缂栬瘧鐨勮ˉ涓佸畨瑁呭埌鐪熷疄搴旂敤杩涚▼锛岄噸鏀捐姹?鎿嶄綔锛屾瘮杈冨畨瑁呭墠鍚庤涓恒€?鏈褰曞彧瑕嗙洊宸插疄闄呰窇閫氱殑 nginx 閮ㄥ垎锛涘叾浣欑敤渚嬪垪鍑洪樆濉炲師鍥犮€?
## 宸插畬鎴?
### 鐪熷疄 nginx 1.31.6 + CVE-2026-27654

- 浜岃繘鍒讹細`build/benchmark20/nginx-1.31.6/nginx`锛堜粠鏈湴浠撳簱鎷疯礉鍒版湇鍔″櫒 `/tmp/nginx-1.31.6`锛?- 閰嶇疆锛歚/tmp/ngx-replay/nginx.conf`锛屽惎鐢?`dav_methods`锛?- 琛ヤ竵锛歚runtime/dsl/patches/CVE-2026-27654.vg`锛岀敱浜?`ngx_http_dav_copy_move_handler`
  鏄?*鏈湴绗﹀彿**锛屼娇鐢?`runtime/frida/symbols.py` 璁＄畻 offset 鍚庝互
  `浣嶇疆: symbol="...", offset=0x1194c1` 瀹夎锛?- 閲嶆斁锛?
```
baseline COPY /dav/source.txt -> 204
瀹夎 DSL 鍚?COPY /dav/source.txt -> 405
DSL hits = 1
```

缁撹锛?*璇ヨˉ涓佸湪鐪熷疄 nginx 涓婃纭寕杞藉苟鎸夊姩浣滆繑鍥?405銆?*

### 鐪熷疄 nginx 1.31.6 + CVE-2026-42533

- offset 瀹夎鎴愬姛锛宍ngx_http_map_variable` 鍛戒腑 1 娆★紱
- 浣?`/map/ordinary` 鍝嶅簲浠?`200 "mapped"` 鍙樹负 `200 绌篳锛屾湭瑙傚療鍒版槑纭敊璇姸鎬侊紱
- 闇€瑕佽繘涓€姝ョ‘璁?nginx 瀵?`ngx_http_map_variable` 杩斿洖鍊肩殑澶勭悊璺緞锛屾殏涓嶇畻閫氳繃銆?
### 鐪熷疄 nginx 1.31.6 + CVE-2026-93479

- 瀹夎鎴愬姛锛宍ngx_http_script_check_length` 鍛戒腑 222064 娆★紱
- 鍝嶅簲浠嶄负 200锛屽師鍥狅細璇?action 闇€瑕佸啓 `ngx_http_script_engine_t.ip/status`
  锛堝姩浣?writes锛夛紝褰撳墠 DSL 缂栬瘧鍣ㄦ湭瀹炵幇 action writes銆?
## 鏈畬鎴?/ 闃诲

1. **鐪熷疄 PoC 涓嶅湪浠撳簱涓?*锛氬師浠撳簱鍙湁 `build/benchmark20` 鐨勬櫘閫氬姛鑳借姹傝鏂?   锛坄experiments/postdeploy/benchmark20/suite.py`锛夛紝娌℃湁 20 涓湡瀹?exploit PoC銆?2. **澶氭暟搴旂敤绗﹀彿鏄湰鍦扮鍙?*锛欴SL 宸叉敮鎸?`offset`锛屼絾姣忎釜 app build 闇€瑕佺敓鎴?   offset 琛紱20 涓?DSL 鏂囦欢褰撳墠鍙啓 symbol銆?3. **action writes 鏈疄鐜?*锛氬奖鍝?93479銆?2945銆?256锛堝啓 engine 瀛楁锛夈€?4. **PHP/Brotli**锛氭湇鍔″櫒娌℃湁瀵瑰簲鐪熷疄浜岃繘鍒?閰嶇疆锛涢渶鍏堟瀯寤烘垨鎷疯礉銆?5. **httpd 闇€妯″潡**锛歚httpd` 浜岃繘鍒堕渶瑕?`mod_*.so` 涓?APR 鐜锛涗笖 httpd 澶氱嚎绋嬶紝
   褰撳墠 DSL 鐨?Frida NativeCallback 鍙€傚悎鍗曠嚎绋嬶紙鍙敼 `ThreadsPerChild 1` 鍐嶆祴锛夈€?6. 鐜版湁 20 渚?DSL 鐨勨€滈獙璇佲€濇槸鍚堟垚 fixture + selector 娉ㄥ叆锛屼笉鏄湡瀹炲簲鐢紱
   鏈褰曟槸鐪熷疄搴旂敤閲嶆斁鐨勭涓€姝ャ€?
## 涓嬩竴姝?
1. 涓烘瘡涓?app build 鐢熸垚 offset 琛紝鎵归噺鎶?20 涓?DSL 鐨?`浣嶇疆` 琛ユ垚 module+offset锛?2. 瀹炵幇 action writes锛坋ngine 瀛楁/鍔ㄤ綔鍓綔鐢級锛?3. 鏋勫缓/鎷疯礉 nginx/httpd/PHP/Brotli 鐪熷疄鐩爣锛屽啓 replay harness锛?   - 鍚姩搴旂敤 鈫?Frida 瀹夎 DSL 鈫?鍙戣姹?鎿嶄綔 鈫?姣旇緝 baseline/patched锛?4. 瀵规潯浠惰ˉ涓佹瀯閫犺Е鍙戣姹傦紙alias/uri_changed銆乺egex captures銆乥locked 闃堝€肩瓑锛夈€?


## 追加：return-only 转换后的真实重放（2026-11-16）

- CVE-2026-93479：改挂 `ngx_http_script_run`，返回 NULL；
  `/dynamic/file.txt?dir=www` baseline 200 → patched **500**，hit 1；
- CVE-2026-42945：改挂 `ngx_http_rewrite_handler`，返回 500；
  `/rewrite/ordinary` baseline 302 → patched **500**，hit 1；
- CVE-2026-9256 与 42945 共用同一 return-only 模板。

分析见 `docs/ai/DSL_RETURN_ONLY_ANALYSIS.md`。


## 追加：Shadow VM 路径真实重放（2026-11-16）

DSL 已改为默认编译到 `runtime/vm.c` 字节码，通过 Frida bridge 安装：

- CVE-2026-27654：DAV COPY baseline 204 → patched **405**，hit 1；
- CVE-2026-93479：dynamic 200 → patched **500**，hit 1；
- CVE-2026-42945：rewrite 302 → patched **500**，hit 1；
- 合成 fixture VM 验证：**26/26**。
