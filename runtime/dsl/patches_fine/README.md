# 细粒度 DSL 补丁与安装交接

基线 `8a1e5c6` 收录 20 个 CVE。`patches/` 中有 13 个补丁文件使用 `if (true)`，共 14 个无条件拦截点。这些规则会接管挂载函数的每次调用。此前的真实应用记录主要验证了挂载和返回值变化，其中部分案例的正常功能也被关闭。原规则可作为对照，细粒度候选可通过 `--dsl` 逐条选用。

## 已实现的候选

| 补丁 | 拦截条件与正常行为 | 安装核对 |
| --- | --- | --- |
| [CVE-2026-56154](CVE-2026-56154.vg) | 直接 `LA-U` / `LA-F` 的 HTTP 头部预查返回空字符串。普通变量、普通头部读取、非头部预查及 `Host` 预查继续执行。上游修复可以保留受影响预查的实际值，候选规则会丢弃该值。 | Apache httpd 2.4.68，`mod_rewrite.so`，`lookup_variable(char *, rewrite_ctx *)`，字符串参数在第 1 位。 |
| [CVE-2026-56449](CVE-2026-56449.vg) | 关闭扩展重写时，跳过 `dump_content` 对空缓冲区的额外处理。前面的注释输出和对非空缓冲区的处理继续执行。 | Apache httpd 2.4.68，`mod_proxy_html.so`，`dump_content(saxctxt *)`。核对 LP64 下 `saxctxt.cfg`、`saxctxt.vb.buf`、`saxctxt.vb.strlen` 与 `proxy_html_conf.extfix` 的偏移为 `8`、`32`、`48`、`56`。 |
| [CVE-2026-93546](CVE-2026-93546.vg) | 读取命名空间时，仅对越界编号返回空字符串。合法编号仍由原函数查找。覆盖上游修复的读取分支，命名空间写入上限与属性数据库打开校验仍需上游修复。 | Apache httpd 2.4.68，`mod_dav_fs.so`，`dav_get_ns_table_uri(dav_db *, int)`。核对 LP64 下有符号 16 位字段 `dav_db.ns_count` 的偏移为 `48`。 |
| [CVE-2026-27654](CVE-2026-27654.vg) | 已通过请求体检查的 COPY/MOVE，若原始 `Destination` 长度已短于普通前缀 alias，则在替换请求 URI 前返回 400。当只有解析后的长度过短时，仍需上游检查。 | nginx 1.29.6 Debian bookworm amd64，Build ID `24ffa74c6144d36f19d953cfa960ff2e7df0fdb2`。已从匹配的 DWARF 核对偏移，并确认原 handler 在请求体检查后进入 `ngx_http_dav_copy_move_handler.part.0`。目标需向符号解析器提供该局部符号。 |
| [CVE-2026-42055](CVE-2026-42055.vg) | 检查 HTTP/2 代理和 gRPC 在入口已知的方法、URI 长度，以及静态代理配置中的适用 Host 长度。保留标准方法与未超限路径。动态生成的字段和转义后才超限的值仍需上游检查。 | nginx 1.31.1 Debian bookworm amd64。偏移已对照该版本官方调试包核对。两个挂载符号分别为 `ngx_http_proxy_v2_create_request` 和 `ngx_http_grpc_create_request`。安装包须启用对应模块并向解析器提供局部符号。 |
| [CVE-2026-42533](CVE-2026-42533.vg) | 正则执行前，仅在请求已有捕获向量、捕获计数非零且将重新分配时，提前返回 `NGX_ERROR`，保留原捕获状态。其他正则调用照常执行。该共享入口覆盖 map 和其他满足条件的调用者，上游修复还覆盖向量为空的分配分支。 | nginx 1.31.2 Debian bookworm amd64，`ngx_http_regex_exec`。偏移已对照官方调试包核对，包括捕获计数偏移 `1096`、向量偏移 `1104`、标志偏移 `1210`。 |
| [CVE-2026-42945](CVE-2026-42945.vg) | 在 `ngx_http_script_regex_end_code` 入口清除 `is_args`，然后执行原逻辑。原函数继续清除 `quote`、处理重写结果和推进脚本。 | nginx 1.29.6 Debian bookworm amd64，Build ID `24ffa74c6144d36f19d953cfa960ff2e7df0fdb2`。从匹配 DWARF 和 ELF 核对了入口与位布局。安装前验证 Build ID。 |
| [CVE-2026-56153](CVE-2026-56153.vg) | 只在续接跨 bucket 字符时检查剩余容量。若当前 bucket 无法完整容纳在字符缓冲区剩余空间中，则返回 `APR_INCOMPLETE`。这是严格候选，合法拆分字符后跟较长文本时也可能被拒绝。 | Apache httpd 2.4.68，`mod_charset_lite.so`，`finish_partial_char`。同时覆盖输入和输出过滤器，目标需保留该函数入口，并核对 `ctx.saved` 偏移 `32` 和缓冲区容量 `8`。 |
| [CVE-2026-57941](CVE-2026-57941.vg) | 仅在发送 DATA 回调进入时发现共享临时 brigade 已有内容，才在写帧前返回回调错误。空 brigade 正常发送。关闭流时的 brigade 复用仍需上游修复。 | Apache httpd 2.4.68，`mod_http2.so`，`on_send_data_cb`。核对 LP64 下 `h2_session.bbtmp` 偏移 `416` 及 APR brigade 链表头偏移 `8`。 |
| [CVE-2026-63686](CVE-2026-63686.vg) | 在 APR 转换入口仅拒绝空转换句柄，继续处理合法转换。旧版 xml2enc 沿自身无效输入分支处理这类错误，上游修复还负责转发剩余 bucket。 | Apache httpd 2.4.68，Linux x86-64，APR-Util 1.6.3 动态库的 `apr_xlate_conv_buffer`。核对运行时 basename，本例为 `libaprutil-1.so.0.6.3`。该入口也覆盖其他 APR 调用者传入空句柄的情况。 |
| [CVE-2026-109619](CVE-2026-109619.vg) | 模块激活后处理 multipart，且没有上一个回调需要执行时，直接返回成功。保留启动期上传进度与已有回调链。启动期全局状态清理仍需上游修复，PHP 的临时配置缓解仍适用。 | PHP 8.5.11 NTS，Linux x86-64，核对 `core_globals.modules_activated` 的偏移 `488`，并确认二进制保留 `php_session_rfc1867_callback` 和 `php_session_rfc1867_orig_callback`。 |

补丁条件依据上游安全公告与发布修改。[Apache httpd 安全公告](https://httpd.apache.org/security/vulnerabilities_24.html) · [Apache 2.4.68 至 2.4.69](https://github.com/apache/httpd/compare/2.4.68...2.4.69) · [PHP 8.5.12 源码](https://github.com/php/php-src/blob/php-8.5.12/ext/session/session.c) · [PHP 安全公告](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)

拦截候选使用只读 VM。`42945` 使用安装器的 [函数入口修复](../README.md#函数入口状态修复)，仅清除指定参数字节的标志位。其余符号挂载需要在目标构建中保留独立函数入口，且模块名须与实际运行时一致。涉及结构偏移的规则须用安装目标的调试符号或编译探针核对布局。

## 验证与交接

```sh
python -m pytest -q tests/test_dsl_fine.py
python -m runtime.dsl.run --dsl runtime/dsl/patches_fine/CVE-2026-56154.vg --check
```

回归测试把合成状态传给真实 Shadow VM，检查放行、拦截和边界值。安装阶段还需在目标 Linux 构建确认符号与 ABI，再验证对应的正常请求和返回值。

安装 Frida 后，测试还会在原生合成函数上验证 `42945` 的标志位更新、相邻字节保留、Build ID 拒绝及原函数调用。目标 nginx 的在线安装与 Rewrite 请求回归待验收。

| 其余无条件规则或已知异常 | 收窄所需的条件或能力 |
| --- | --- |
| nginx `9256` | 需要在分配前按每段捕获的实际转义长度计数，在正则启动成功后重置脚本标志，并在复杂值求长前将该标志传给局部引擎。入口清标志会影响未匹配和错误分支。运行时移植需要挂在匹配成功后、分配前的路径，并同步复杂值求长处的局部状态。 |
| nginx `93479` | 目录中已有长度判断实验。真实应用记录显示返回式短路可能阻止脚本推进。上游错误分支同时更新脚本指令指针和状态，安装验收须覆盖这两项。 |
| httpd `63292` | 最小等价改动是在写入实际展开片段前校验长度，并让展开函数向 `mva_translate` 传播 414，使其在 CGI 后续处理前退出。原函数返回 `void`。函数入口预检还要重现主机名来源、模板取段和 CGI 选择，上游模块修复可直接复用实际展开状态。 |

nginx 的适用版本与检查条件可在上游公告、发布差异和调试包中核对。[nginx 安全公告](https://nginx.org/en/security_advisories.html) · [DAV 上游修改](https://github.com/nginx/nginx/compare/release-1.29.6...release-1.29.7) · [HTTP/2 代理与 gRPC 上游修改](https://github.com/nginx/nginx/compare/release-1.31.1...release-1.31.2) · [正则捕获上游修改](https://github.com/nginx/nginx/compare/release-1.31.2...release-1.31.3) · [Debian 调试包索引](https://nginx.org/packages/mainline/debian/pool/nginx/n/nginx/)

Rewrite 状态修复与虚拟主机错误传播可对照发布源码。[nginx 1.31.0 Rewrite](https://github.com/nginx/nginx/blob/release-1.31.0/src/http/ngx_http_script.c) · [nginx 1.31.1 Rewrite](https://github.com/nginx/nginx/blob/release-1.31.1/src/http/ngx_http_script.c) · [Apache 2.4.69 mod_vhost_alias](https://github.com/apache/httpd/blob/2.4.69/modules/mappers/mod_vhost_alias.c)
