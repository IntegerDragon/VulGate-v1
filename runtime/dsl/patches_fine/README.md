# 细粒度 DSL 补丁与安装交接

基线 `8a1e5c6` 收录 20 个 CVE。`patches/` 中有 13 个补丁文件使用 `if (true)`，共 14 个无条件拦截点。这些规则会接管挂载函数的每次调用。此前的真实应用记录主要验证了挂载和返回值变化，其中部分案例的正常功能也被关闭。原规则可作为对照，细粒度候选可通过 `--dsl` 逐条选用。

## 本批候选

| 补丁 | 拦截条件与正常行为 | 安装核对 |
| --- | --- | --- |
| [CVE-2026-56154](CVE-2026-56154.vg) | 直接 `LA-U` / `LA-F` 的 HTTP 头部预查返回空字符串。普通变量、普通头部读取、非头部预查及 `Host` 预查继续执行。上游修复可以保留受影响预查的实际值，候选规则会丢弃该值。 | Apache httpd 2.4.68，`mod_rewrite.so`，`lookup_variable(char *, rewrite_ctx *)`，字符串参数在第 1 位。 |
| [CVE-2026-56449](CVE-2026-56449.vg) | 关闭扩展重写时，跳过 `dump_content` 对空缓冲区的额外处理。前面的注释输出和对非空缓冲区的处理继续执行。 | Apache httpd 2.4.68，`mod_proxy_html.so`，`dump_content(saxctxt *)`。核对 LP64 下 `saxctxt.cfg`、`saxctxt.vb.buf`、`saxctxt.vb.strlen` 与 `proxy_html_conf.extfix` 的偏移为 `8`、`32`、`48`、`56`。 |
| [CVE-2026-93546](CVE-2026-93546.vg) | 读取命名空间时，仅对越界编号返回空字符串。合法编号仍由原函数查找。覆盖上游修复的读取分支，命名空间写入上限与属性数据库打开校验仍需上游修复。 | Apache httpd 2.4.68，`mod_dav_fs.so`，`dav_get_ns_table_uri(dav_db *, int)`。核对 LP64 下有符号 16 位字段 `dav_db.ns_count` 的偏移为 `48`。 |

源码依据。[Apache httpd 安全公告](https://httpd.apache.org/security/vulnerabilities_24.html) · [2.4.68 至 2.4.69 的上游修改](https://github.com/apache/httpd/compare/2.4.68...2.4.69)

三个候选均使用现有 DSL 格式与只读 VM。表中的符号需要在目标构建中保留独立函数入口，且 `.so` 模块名须与实际运行时一致。优化后函数可能内联或改名。涉及结构偏移的规则须用安装目标的调试符号或编译探针核对布局。

## 验证与交接

```sh
python -m pytest -q tests/test_dsl_fine.py
python -m runtime.dsl.run --dsl runtime/dsl/patches_fine/CVE-2026-56154.vg --check
```

回归测试把合成状态传给真实 Shadow VM，检查放行、拦截和边界值。安装阶段还需在目标 Linux 构建确认符号与 ABI，并跑正常请求回归，分别检查预查结果、HTML 注释保留和合法 WebDAV 属性读取。

| 其余无条件规则或已知异常 | 收窄所需的条件或能力 |
| --- | --- |
| nginx `27654` | 在 COPY/MOVE 已解析目标 URI、尚未修改请求对象时检查长度和 alias。当前调用点支持观察，返回拦截只能挂在函数入口。 |
| nginx `42055` | 在代理与 gRPC 请求构建中检查实际编码的 method、URI、host 和 header 长度。函数入口的原始长度无法覆盖重写和配置生成的值。 |
| nginx `42533` | 上游在正则捕获缓冲区重分配时同步清零捕获数量。现有 map 函数入口无法完成状态同步。 |
| nginx `42945`、`9256` | 上游修改 rewrite 脚本转义状态及缓冲区长度计算。现有 handler 返回 500 会影响正常 rewrite。需要脚本状态修复或可安全中止的挂载点。 |
| nginx `93479` | 目录中已有长度判断实验。真实应用记录显示返回式短路可能阻止脚本推进。上游错误分支同时更新脚本指令指针和状态，安装验收须覆盖这两项。 |
| httpd `56153` | 字符集转换在循环内追加跨 bucket 的字符字节。需要在每次写入前检查可用容量。函数入口只能看到初始状态。 |
| httpd `57941` | 上游改为每次回调使用独立 brigade，以处理重入。仅改连接初始化的返回值会关闭 HTTP/2。 |
| httpd `63292` | 需要检查实际展开片段的长度，并从受影响版本的 `void` helper 向 HTTP 调用者传播 414。 |
| httpd `63686` | 需要捕获转换过程的返回值，并在同一次过滤调用中处理剩余 bucket 和后续过滤器。 |
| PHP `109619` | 现有规则整体关闭上传进度回调。要保留进度功能，需要覆盖 PHP 请求结束时的全局状态清理。 [PHP 安全发布说明](https://www.php.net/archive/2026.php) |

nginx 源码与版本依据。[nginx 安全公告](https://nginx.org/en/security_advisories.html) · [DAV 上游修改](https://github.com/nginx/nginx/compare/release-1.29.6...release-1.29.7)
