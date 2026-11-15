# 鎴愮啛 Hook 搴撳彲琛屾€ф祴璇曪紙鐑寕杞?+ 澶氱嚎绋嬭繍琛屼腑瀹夎/鍗歌浇锛?
鐩爣锛氬洖绛斾袱涓棶棰樷€斺€?*鎴愮啛搴撹兘鍚︾敤浜庣儹琛ヤ竵**锛屼互鍙?*绾跨▼鎸佺画杩愯鏃跺畨瑁?鍗歌浇鏄惁瀹夊叏**銆?
## 娴嬭瘯鐜

- WSL Ubuntu 24.04銆亁86-64銆乬cc 13銆丗rida 17.26.2锛堜粎浣滀负鈥滆繍琛屾椂娉ㄥ叆鍣ㄢ€濓紝鎶婃祴璇?agent `.so` 鍔犺浇杩涚洰鏍囧苟璋冪敤鍏跺鍑哄嚱鏁帮級锛?- 鐩爣杩涚▼锛? 涓?pthread 鎸佺画璋冪敤 `target_fn(int)`锛堟棤 sleep锛岀儹寰幆锛夛紝涓荤嚎绋嬬敤 stdin 鍛戒护
  `status / call / pause / resume / exit` 鏌ヨ锛?- 娴嬭瘯 agent锛氬簱 + `runtime/vm.c`锛堥潤鎬佸祵鍏ワ級锛実uard 鍛戒腑 BLOCK 杩斿洖 -73锛孭ASS 璋冨師鍑芥暟锛?- 姣忚疆瀹夎鍚庣瓑寰?10ms 鍐嶅嵏杞斤紝閲嶅 50 杞紝缁熻鐩爣鏄惁瀛樻椿銆乥locked 璁℃暟銆佸嵏杞藉悗璋冪敤鏄惁鎭㈠ 105銆?
## 搴撲笌缁撴灉

| 搴?| 鏈哄埗 | 鐗堟湰 | 鐑寕杞?| 杩愯涓畨瑁?鍗歌浇 | 缁撹 |
|---|---|---|---|---|---|
| **funchook** | inline hook锛堝啓鍑芥暟鍏ュ彛璺宠浆锛?| `b499170` | 鉁?Frida 娉ㄥ叆 agent 鍚庤皟鐢?| 鉂?鏃?STW 鏃?3 娆?50 杞疄楠岋細1 娆￠€氳繃锛?*2 娆＄洰鏍囪繘绋嬪穿婧?*锛圔rokenPipe锛夛紱鍔犺嚜瀹炵幇 STW 鍚?**3脳50 杞叏閮ㄩ€氳繃** | 寮曟搸鍙敤锛屼絾 install/uninstall **蹇呴』閰?stop-the-world** |
| **plthook** | GOT/PLT 琛ㄩ」鏀瑰啓 | `24c69df`锛堝凡褰掓。锛?| 鉁?| 鉁?3 娆?脳 50 杞叏閮ㄩ€氳繃锛岀洰鏍囧瓨娲伙紝blocked 璁℃暟鎸佺画澧為暱 | 鍙畨鍏ㄧ儹瀹夎/鍗歌浇锛屼絾鍙鐩?PLT 璋冪敤 |
| Dobby | inline hook | 浠撳簱 HEAD | 缂栬瘧澶辫触 | 鏈祴 | GCC 涓嬬紪璇戦棶棰橈紙`__has_feature`銆佸ご鏂囦欢/缁撴瀯涓嶄竴鑷达級锛屾湰鏈烘湭璺戦€?|
| subhook | inline hook | 鈥?| clone 澶辫触 | 鏈祴 | GitHub clone/褰掓。涓嬭浇澶氭瓒呮椂锛堢綉缁滈檺鍒讹級 |
| Frida Gum devkit | Gum C API | 17.26.2 | 涓嬭浇澶辫触 | 鏈祴 | release 璧勪骇涓嬭浇琚綉缁滈樆鏂紱Frida JS 璺緞鐨勫凡鐭ラ檺鍒惰 `FRIDA_THREAD_SAFETY.md` |

### funchook 缁嗚妭

- inline hook 鏈韩宸ヤ綔姝ｅ父锛氬畨瑁呭悗 worker 绾跨▼澶ч噺杩斿洖 -73锛宍hook_blocked` 杈?300 涓?锛涘嵏杞藉悗 `call` 鎭㈠ 105锛?- 浣?4 绾跨▼鎸佺画璋冪敤鏃讹紝瀹夎/鍗歌浇绐楀彛鍐呬細鍑虹幇鐩爣杩涚▼鐩存帴宕╂簝锛? 娆￠噷 2 娆★級锛?- 鐩爣搴旂敤灞?`pause`锛坵orker 鑷棆绛夊緟锛夊悗锛岃繛缁?30 娆″畨瑁?鍗歌浇鍏ㄩ儴姝ｇ‘锛屾棤宕╂簝锛?- funchook 鐨?`funchook_install/uninstall` 娌℃湁鈥滃仠姝㈠叾浠栫嚎绋嬧€濈殑閫夐」锛坒lags 淇濈暀涓?0锛夛紝绗﹀悎鍏堕潪绾跨▼瀹夊叏鐨勯鏈熴€?
### plthook 缁嗚妭

- 浣跨敤鈥滀富绋嬪簭 鈫?鍏变韩搴撳鍑哄嚱鏁扳€濈殑 PLT 璋冪敤鐩爣锛坄target_plt` + `libtarget_shared.so`锛夛紱
- 3 娆?脳 50 杞畨瑁?鍗歌浇鍏ㄩ儴閫氳繃锛岀洰鏍囧瓨娲伙紱blocked 璁℃暟涓?`hook_blocked` 涓€鑷村闀匡紱
- 瀵?*鑷寘鍚洰鏍?*锛堝悓涓€鍙墽琛屾枃浠跺唴鐩存帴璋冪敤 `target_fn`锛夊畨瑁呰繑鍥?`-3`锛堟壘涓嶅埌 PLT 琛ㄩ」锛夛紝璇存槑鍏惰鐩栬寖鍥翠弗鏍煎彈闄愩€?
## STW锛坰top the world锛夊疄鐜颁笌楠岃瘉

`stw.c` 瀹炵幇浜嗕竴濂楃敤鎴锋€佷俊鍙峰仠杞︼細

1. 娉ㄥ叆鍣ㄥ湪 Frida attach **涔嬪墠**璇诲彇 `/proc/<pid>/task`锛屾妸鐩爣绾跨▼鍒楄〃浼犵粰 agent锛坄test_set_threads`锛夛紝Frida 鑷繁鐨?helper 绾跨▼涓嶄細琚仠锛?2. install/uninstall 鍓嶅悜姣忎釜鐩爣绾跨▼鍙?`SIGRTMIN+4`锛沨andler 璁板綍 `(tid, RIP)` 鍚庤嚜鏃嬬瓑寰?release锛?3. handler 鐢?**epoch 璁℃暟**绛夊緟閲婃斁锛岄伩鍏嶁€滀笂涓€杞俊鍙峰欢杩熷埌杈?+ 涓嬩竴杞噸缃爣蹇椻€濇妸绾跨▼姘镐箙鍋滀綇锛?4. 鍋滆溅鍚庢鏌ユ瘡涓嚎绋嬬殑 PC 鏄惁钀藉湪琚鐩栫殑鍑芥暟鍏ュ彛 16 瀛楄妭鍐咃紱鑻ュ湪锛岄噴鏀惧悗閲嶈瘯锛堟渶澶?50 娆★紝闂撮殧 200碌s锛夛紝鐩村埌鎵€鏈夌嚎绋嬮兘涓嶅湪琛ヤ竵鍖哄煙锛?5. patch/鎭㈠瀹屾垚鍚庣疆 release锛岀瓑鎵€鏈夌嚎绋嬬寮€ handler銆?
楠岃瘉缁撴灉锛?
| 鍦烘櫙 | 缁撴灉 |
|---|---|
| funchook 鏃?STW锛?脳50 杞?live 瀹夎/鍗歌浇 | 1 娆￠€氳繃锛?*2 娆＄洰鏍囧穿婧?* |
| funchook + STW锛?脳50 杞?live 瀹夎/鍗歌浇 | **3 娆″叏閮ㄩ€氳繃**锛岀洰鏍囧瓨娲伙紝blocked 璁℃暟鎸佺画澧為暱锛屽嵏杞藉悗 `call` 鎭㈠ 105 |
| funchook + STW锛宲ause 鍚庡畨瑁?鎭㈠ | 閫氳繃锛堟仮澶嶅悗 worker 缁х画姝ｅ父璁℃暟锛?|
| plthook 鏃?STW | 3脳50 杞€氳繃锛圙OT 鎸囬拡鍘熷瓙鍐欙紝涓嶉渶瑕?STW锛?|

瀹炴祴 STW 寮€閿€锛氫竴娆?install 閫氬父闇€瑕?1鈥? 杞仠杞︼紙姣忚疆 ~0.1鈥?ms锛夛紝涓昏鍦ㄧ瓑绾跨▼杩涘叆 handler 涓庨伩寮€ PC 钀藉湪琛ヤ竵鍖哄煙鐨勭嚎绋嬶紱杩愯鏈熸棤棰濆寮€閿€銆?
### 涓荤嚎绋嬭皟鐢ㄦ寕璧凤細瀹氫綅涓庝慨澶?
鏃╂湡鐗堟湰涓紝hook 瀹夎鍚庝粠鐩爣**涓荤嚎绋?*璋冪敤 `target_fn` 浼氬嚭鐜扳€滄棤鍝嶅簲鈥濓紝鑰?worker 绾跨▼璋冪敤姝ｅ父銆傚畾浣嶈繃绋嬶細

- 鍦?guard 鍐呮墦鐐癸紙杩涘叆 `G`銆佽皟鐢?VM 鍓?`V`銆佽繑鍥炲悗 `D`銆佸懡涓?BLOCK `R`锛夛紝骞惰 target 鎶?`call` 鐨勮繘鍏?閫€鍑?鎵撳嵃鍐欏叆 `/tmp/vg_target_trace`锛涗慨澶嶅悗姣忔涓荤嚎绋嬭皟鐢ㄩ兘鑳界湅鍒板畬鏁?`GVDR` 涓?`call-enter/exit/printed`锛?- 閫氳繃 Frida RPC 鐩存帴璋冪敤 guard 鍑芥暟锛堜笉缁忚繃 hook锛夊缁堟甯革紝璇存槑 guard/VM 鏈韩娌￠棶棰橈紱
- 鍞竴涓€娆″彲澶嶇幇鐨勬寕璧峰嚭鐜板湪涓€娆?**STW dirty-PC 妫€鏌ュけ璐ャ€乽ninstall 杩斿洖 -2** 涔嬪悗锛涜璺緞浼氭妸 hook 鐣欏湪宸插畨瑁呯姸鎬佸苟缁х画鍚庣画璋冪敤锛?- 鎹淇浜嗕笁澶勬椂搴忛棶棰橈細
  1. **VM program 鍦?install 闃舵鍒濆鍖?*锛堣€屼笉鏄?guard 棣栨璋冪敤鏃舵噿鍒濆鍖栵級锛宍program_ready` 鐢ㄥ師瀛愬彉閲忥紱
  2. install/uninstall 鐨?STW 閮?*閲嶈瘯鐩村埌鎵€鏈夌嚎绋?RIP 涓嶅湪琛ヤ竵 16 瀛楄妭绐楀彛鍐?*锛堟渶澶?50 娆★級锛?  3. STW 鏀逛负 **epoch 閲婃斁鍗忚**锛歨andler 绛夊緟鈥滈噴鏀?epoch 鈮?杩涘叆 epoch鈥濓紝杞涔嬮棿涓嶄細鎶婃棫 handler 鐨勯噴鏀炬爣蹇楅噸缃紱姣忚疆寮€濮嬪墠绛夊緟涓婁竴杞?handler 鍏ㄩ儴閫€鍑猴紝瓒呮椂 500ms銆?
楠岃瘉锛堜慨澶嶅悗锛夛細

- 涓荤嚎绋?`pause` 鍚庤繛缁?**200 杞?* install 鈫?`call`(-73) 鈫?uninstall 鈫?`call`(105)锛氬叏閮ㄩ€氳繃锛岀洰鏍囧瓨娲伙紱
- 鍘熸寕璧峰鐜拌剼鏈噸澶?**5 娆?*锛氬叏閮ㄩ€氳繃锛?- 浠呭仛 patch 寰幆锛坵orker pause锛屼笉璋冪敤 hook锛?*500 杞?*锛氬叏閮ㄩ€氳繃锛?- live锛? worker 鐑惊鐜€?0 杞?install/uninstall锛夎繛缁?5 娆★細**3 娆″畬鍏ㄩ€氳繃锛? 娆″湪缁撴潫闃舵鐩爣浠?SIGSEGV/-9 閫€鍑?*锛堜笉鏄富绾跨▼璋冪敤鎸傝捣锛屽彂鐢熷湪娴嬭瘯鏀跺熬/detach 鍓嶅悗锛夈€傚洜姝や富绾跨▼璋冪敤闂宸蹭慨澶嶏紝浣嗏€滈珮棰?live patch + teardown鈥濅粛鏈夋畫浣欑珵鎬併€?
### 娈嬩綑闄愬埗

- **live patch 浠嶅伓鍙戠粨鏉熼樁娈靛穿婧?鎸傝捣**锛圫IGSEGV 鎴栨湭閫€鍑猴級锛屽嵆浣挎崲鎴愮畝鍗曞父閲?guard 涔熶細鍑虹幇 鈫?闂鍦?inline patch/STW 涓?funchook 鐨勪氦浜掞紝涓嶅湪 VM/涓荤嚎绋嬶紱褰撳墠鍙敤鐨勭ǔ瀹氭ā寮忔槸**quiesced锛堢洰鏍囩嚎绋嬫殏鍋滃悗鍐?patch锛?*锛?- 绾跨▼鍒楄〃鐢辨敞鍏ュ櫒鍦?attach 鍓嶅揩鐓э紝**琛ヤ竵鏈熼棿鏂板缓鐨勭嚎绋嬩笉浼氳鍋?*锛涢渶瑕佸懆鏈熸€ч噸鏂版灇涓炬垨鈥滃厛鍋滀綇鍒涘缓绾跨▼锛坈lone hook锛夆€濓紱
- PC 钀藉湪琛ヤ竵鍖哄煙闈犻噸璇曪紝鏋佺鐑殑灏忓嚱鏁板彲鑳藉娆￠噸璇曪紱
- 淇″彿鍋滆溅瑕佹眰鐩爣绾跨▼鍙淇″彿鎵撴柇锛堥暱鏃堕棿涓嶅彲涓柇鐫＄湢/灞忚斀璇ヤ俊鍙蜂細瓒呮椂锛夛紱
- funchook 鐨?trampoline 鍦ㄥ嵏杞藉悗**鏁呮剰涓嶉噴鏀?*锛堥伩鍏嶇嚎绋嬩粛鍦?trampoline 涓椂琚?free 鎴?SIGSEGV锛夛紝浼氬甫鏉ユ瘡娆?patch 鐨勫皯閲忓唴瀛樻硠婕忥紱鐢熶骇闇€鍋?trampoline 鑼冨洿璺熻釜鍚庡啀瀹夊叏閲婃斁銆?
### 鍗曟 live 瀹夎/鍗歌浇楠岃瘉锛堥潪楂橀锛?
鐢?`single_install.py` 妯℃嫙姝ｅ父鐢熶骇鐢ㄦ硶锛? 涓?worker 鎸佺画璋冪敤 鈫?瀹夎涓€娆?鈫?瑙傚療 50ms 鈫?鍗歌浇涓€娆?鈫?瑙傚療 50ms 鈫?涓荤嚎绋嬭皟鐢ㄧ‘璁ゆ仮澶?105 鈫?閫€鍑猴紱姣忎釜妯″紡閲嶅 20 涓繘绋嬨€?
| 妯″紡 | 缁撴灉 | 璇存槑 |
|---|---|---|
| **BLOCK** | **17/20 鎴愬姛** | 瀹夎/鐢熸晥/鍗歌浇/鎭㈠鍧囨纭紱3 娆″け璐ラ兘鏄?*杩涚▼閫€鍑洪樁娈?* SIGSEGV/SIGTRAP锛?11/-5锛夛紝涓嶆槸 patch 閫昏緫閿欒 |
| **PASS** | **0/3 ~ 1/3 鎴愬姛** | live 涓?PASS 璺緞浼氬穿婧冿紱鎶?worker 鏆傚仠鍚?PASS 鍗曟璋冪敤姝ｅ父锛堣繑鍥?105 涓斿師鍑芥暟鎵ц锛?|

缁撹锛?
- **鍗曟 live BLOCK 琛ヤ竵鍩烘湰鍙敤**锛屽墿浣欓棶棰樻槸閫€鍑洪樁娈靛穿婧冿紙闇€瑕佺户缁畾浣?detach/淇″彿娓呯悊锛夛紱
- **PASS 璺緞鍦?live 澶氱嚎绋嬩笅涓嶅彲鐢?*锛堝嵆浣?1 涓?worker 涔熷父宕╋級锛屾€€鐤?funchook 鐨?`real_target` trampoline 鍦ㄥ苟鍙戣皟鐢?闀胯窇涓嬪瓨鍦ㄩ噸鍏ユ垨閲嶅畾浣嶉棶棰橈紱quiesced 涓嬫甯搞€傜敓浜ц嫢闇€瑕?PASS 璇箟锛屽繀椤绘崲鐢ㄨ嚜寤?trampoline 鎴栨敼鐢?plthook/preload銆?
## 缁撹

1. **inline hook 搴擄紙funchook锛変笉鑳界洿鎺ョ敤浜庘€滅嚎绋嬭繍琛屼腑鈥濈殑鐑畨瑁?鍗歌浇**锛涘繀椤婚厤鍚?stop-the-world銆俧unchook 鑷韩涓嶆彁渚涳紝闇€瑕佹垜浠湪娉ㄥ叆鍣?agent 閲屽疄鐜般€?2. **plthook 鍙互瀹夊叏鍦板湪绾跨▼杩愯鏃剁儹瀹夎/鍗歌浇**锛屼絾鍙鐩栫粡杩囧姩鎬佺鍙疯〃锛圥LT锛夌殑璋冪敤锛涢€傚悎浣滀负鈥滃姩鎬佺鍙风儹琛ヤ竵鈥濈殑蹇€熻矾寰勩€?3. Frida 鐨?`Thread.suspend` 鍦?17.26.2 涓笉鍙敤锛堝疄娴?`TypeError: not a function`锛夛紝鍥犳鍋滅嚎绋嬮渶瑕佸湪鍘熺敓灞傚疄鐜帮紝鍊欓€夛細
   - 缁欑洰鏍囨墍鏈夌嚎绋嬪彂淇″彿锛屽湪淇″彿 handler 涓嚜鏃嬬瓑寰呬竴涓師瀛愭爣蹇楋紙handler 鍋滀綇鍚庣敱娉ㄥ叆绾跨▼ patch锛屽啀閲婃斁锛夛紱
   - 澶栭儴 `ptrace(PTRACE_SEIZE)` 閫愪釜绾跨▼鎸傝捣锛堥渶瑕佹潈闄愶紝涓斾笌 Frida 娉ㄥ叆鍏卞瓨闇€楠岃瘉锛夛紱
   - 浣跨敤鎻愪緵 stop-the-world 鐨勫紩鎿庯紙Detours 鏈?`DetourTransactionBegin/Commit`锛涗絾 Windows 鍗曞钩鍙帮級銆?4. 瀵?VulGate 鐨勫彲琛屾柟鍚戯細
   - **鍘熺敓 inline hook + 鑷疄鐜?stop-the-world**锛氭弧瓒崇儹銆佸绾跨▼銆佷笉閲嶅缓銆佷綆杩愯寮€閿€锛?   - **plthook 鐑矾寰?*锛氫笉闇€瑕佸仠绾跨▼锛岃鐩?PLT 绗﹀彿锛涘彲涓庣幇鏈?preload 妯″紡鍏辩敤瑙勫垯/VM锛?   - 涓嶅缓璁妸 funchook 鐩存帴鏀捐繘褰撳墠 Frida JS 璺緞锛涘畠闇€瑕佸師鐢熸敞鍏ュ櫒鎴?CModule/agent 鎵胯浇銆?5. 鏈獙璇侊細ARM64銆乄indows锛圡inHook/Detours锛夈€乵acOS銆佺湡瀹?nginx/httpd 鐩爣銆?
## 澶嶇幇

```sh
# 渚濊禆鏀惧湪 /tmp/mature-hooks锛堣 build.sh 鐨?FUNCHOOK_DIR / PLTHOOK_DIR锛?git clone --depth 1 https://github.com/kubo/funchook.git /tmp/mature-hooks/funchook
cmake -S /tmp/mature-hooks/funchook -B /tmp/mature-hooks/funchook/build -DFUNCHOOK_BUILD_TESTS=OFF
cmake --build /tmp/mature-hooks/funchook/build -j4
git clone --depth 1 https://github.com/kubo/plthook.git /tmp/mature-hooks/plthook

bash experiments/mature-hooks/build.sh
PYTHONPATH=/tmp/vulgate-frida-deps-20261111 python3 experiments/mature-hooks/runner.py \
  --lib experiments/mature-hooks/funchook_agent.so --name funchook --cycles 50
PYTHONPATH=/tmp/vulgate-frida-deps-20261111 python3 experiments/mature-hooks/runner.py \
  --lib experiments/mature-hooks/plthook_agent.so --name plthook \
  --target experiments/mature-hooks/target_plt --cycles 50
```

`runner.py` 鐨勫弬鏁帮細`--cycles`锛堝畨瑁?鍗歌浇杞暟锛夈€乣--quiesced-cycles`锛坧ause 鍚庤疆鏁帮級銆乣--skip-live`銆?`--target`銆乣--result`銆傛湰杞粨鏋滄潵鑷笂杩板懡浠ょ殑澶氭杩愯銆?
