# 成熟 Hook 库可行性测试（热挂载 + 多线程运行中安装/卸载）

目标：回答两个问题——**成熟库能否用于热补丁**，以及**线程持续运行时安装/卸载是否安全**。

## 测试环境

- WSL Ubuntu 24.04、x86-64、gcc 13、Frida 17.26.2（仅作为“运行时注入器”，把测试 agent `.so` 加载进目标并调用其导出函数）；
- 目标进程：4 个 pthread 持续调用 `target_fn(int)`（无 sleep，热循环），主线程用 stdin 命令
  `status / call / pause / resume / exit` 查询；
- 测试 agent：库 + `runtime/vm.c`（静态嵌入），guard 命中 BLOCK 返回 -73，PASS 调原函数；
- 每轮安装后等待 10ms 再卸载，重复 50 轮，统计目标是否存活、blocked 计数、卸载后调用是否恢复 105。

## 库与结果

| 库 | 机制 | 版本 | 热挂载 | 运行中安装/卸载 | 结论 |
|---|---|---|---|---|---|
| **funchook** | inline hook（写函数入口跳转） | `b499170` | ✅ Frida 注入 agent 后调用 | ❌ 3 次 50 轮实验：1 次通过，**2 次目标进程崩溃**（BrokenPipe）；应用层 `pause` 后 30 轮安装/卸载全部通过 | 引擎可用，但 install/uninstall **不是线程安全的**，必须先停线程 |
| **plthook** | GOT/PLT 表项改写 | `24c69df`（已归档） | ✅ | ✅ 3 次 × 50 轮全部通过，目标存活，blocked 计数持续增长 | 可安全热安装/卸载，但只覆盖 PLT 调用 |
| Dobby | inline hook | 仓库 HEAD | 编译失败 | 未测 | GCC 下编译问题（`__has_feature`、头文件/结构不一致），本机未跑通 |
| subhook | inline hook | — | clone 失败 | 未测 | GitHub clone/归档下载多次超时（网络限制） |
| Frida Gum devkit | Gum C API | 17.26.2 | 下载失败 | 未测 | release 资产下载被网络阻断；Frida JS 路径的已知限制见 `FRIDA_THREAD_SAFETY.md` |

### funchook 细节

- inline hook 本身工作正常：安装后 worker 线程大量返回 -73，`hook_blocked` 达 300 万+；卸载后 `call` 恢复 105；
- 但 4 线程持续调用时，安装/卸载窗口内会出现目标进程直接崩溃（3 次里 2 次）；
- 目标应用层 `pause`（worker 自旋等待）后，连续 30 次安装/卸载全部正确，无崩溃；
- funchook 的 `funchook_install/uninstall` 没有“停止其他线程”的选项（flags 保留为 0），符合其非线程安全的预期。

### plthook 细节

- 使用“主程序 → 共享库导出函数”的 PLT 调用目标（`target_plt` + `libtarget_shared.so`）；
- 3 次 × 50 轮安装/卸载全部通过，目标存活；blocked 计数与 `hook_blocked` 一致增长；
- 对**自包含目标**（同一可执行文件内直接调用 `target_fn`）安装返回 `-3`（找不到 PLT 表项），说明其覆盖范围严格受限。

## 结论

1. **inline hook 库（funchook）不能直接用于“线程运行中”的热安装/卸载**；必须配合 stop-the-world。funchook 自身不提供，需要我们在注入器/agent 里实现。
2. **plthook 可以安全地在线程运行时热安装/卸载**，但只覆盖经过动态符号表（PLT）的调用；适合作为“动态符号热补丁”的快速路径。
3. Frida 的 `Thread.suspend` 在 17.26.2 中不可用（实测 `TypeError: not a function`），因此停线程需要在原生层实现，候选：
   - 给目标所有线程发信号，在信号 handler 中自旋等待一个原子标志（handler 停住后由注入线程 patch，再释放）；
   - 外部 `ptrace(PTRACE_SEIZE)` 逐个线程挂起（需要权限，且与 Frida 注入共存需验证）；
   - 使用提供 stop-the-world 的引擎（Detours 有 `DetourTransactionBegin/Commit`；但 Windows 单平台）。
4. 对 VulGate 的可行方向：
   - **原生 inline hook + 自实现 stop-the-world**：满足热、多线程、不重建、低运行开销；
   - **plthook 热路径**：不需要停线程，覆盖 PLT 符号；可与现有 preload 模式共用规则/VM；
   - 不建议把 funchook 直接放进当前 Frida JS 路径；它需要原生注入器或 CModule/agent 承载。
5. 未验证：ARM64、Windows（MinHook/Detours）、macOS、真实 nginx/httpd 目标。

## 复现

```sh
# 依赖放在 /tmp/mature-hooks（见 build.sh 的 FUNCHOOK_DIR / PLTHOOK_DIR）
git clone --depth 1 https://github.com/kubo/funchook.git /tmp/mature-hooks/funchook
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

`runner.py` 的参数：`--cycles`（安装/卸载轮数）、`--quiesced-cycles`（pause 后轮数）、`--skip-live`、
`--target`、`--result`。本轮结果来自上述命令的多次运行。
