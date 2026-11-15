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
| **funchook** | inline hook（写函数入口跳转） | `b499170` | ✅ Frida 注入 agent 后调用 | ❌ 无 STW 时 3 次 50 轮实验：1 次通过，**2 次目标进程崩溃**（BrokenPipe）；加自实现 STW 后 **3×50 轮全部通过** | 引擎可用，但 install/uninstall **必须配 stop-the-world** |
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

## STW（stop the world）实现与验证

`stw.c` 实现了一套用户态信号停车：

1. 注入器在 Frida attach **之前**读取 `/proc/<pid>/task`，把目标线程列表传给 agent（`test_set_threads`），Frida 自己的 helper 线程不会被停；
2. install/uninstall 前向每个目标线程发 `SIGRTMIN+4`；handler 记录 `(tid, RIP)` 后自旋等待 release；
3. handler 用 **epoch 计数**等待释放，避免“上一轮信号延迟到达 + 下一轮重置标志”把线程永久停住；
4. 停车后检查每个线程的 PC 是否落在被覆盖的函数入口 16 字节内；若在，释放后重试（最多 50 次，间隔 200µs），直到所有线程都不在补丁区域；
5. patch/恢复完成后置 release，等所有线程离开 handler。

验证结果：

| 场景 | 结果 |
|---|---|
| funchook 无 STW，3×50 轮 live 安装/卸载 | 1 次通过，**2 次目标崩溃** |
| funchook + STW，3×50 轮 live 安装/卸载 | **3 次全部通过**，目标存活，blocked 计数持续增长，卸载后 `call` 恢复 105 |
| funchook + STW，pause 后安装/恢复 | 通过（恢复后 worker 继续正常计数） |
| plthook 无 STW | 3×50 轮通过（GOT 指针原子写，不需要 STW） |

实测 STW 开销：一次 install 通常需要 1–5 轮停车（每轮 ~0.1–1ms），主要在等线程进入 handler 与避开 PC 落在补丁区域的线程；运行期无额外开销。

### 主线程调用挂起：定位与修复

早期版本中，hook 安装后从目标**主线程**调用 `target_fn` 会出现“无响应”，而 worker 线程调用正常。定位过程：

- 在 guard 内打点（进入 `G`、调用 VM 前 `V`、返回后 `D`、命中 BLOCK `R`），并让 target 把 `call` 的进入/退出/打印写入 `/tmp/vg_target_trace`；修复后每次主线程调用都能看到完整 `GVDR` 与 `call-enter/exit/printed`；
- 通过 Frida RPC 直接调用 guard 函数（不经过 hook）始终正常，说明 guard/VM 本身没问题；
- 唯一一次可复现的挂起出现在一次 **STW dirty-PC 检查失败、uninstall 返回 -2** 之后；该路径会把 hook 留在已安装状态并继续后续调用；
- 据此修复了三处时序问题：
  1. **VM program 在 install 阶段初始化**（而不是 guard 首次调用时懒初始化），`program_ready` 用原子变量；
  2. install/uninstall 的 STW 都**重试直到所有线程 RIP 不在补丁 16 字节窗口内**（最多 50 次）；
  3. STW 改为 **epoch 释放协议**：handler 等待“释放 epoch ≥ 进入 epoch”，轮次之间不会把旧 handler 的释放标志重置；每轮开始前等待上一轮 handler 全部退出，超时 500ms。

验证（修复后）：

- 主线程 `pause` 后连续 **200 轮** install → `call`(-73) → uninstall → `call`(105)：全部通过，目标存活；
- 原挂起复现脚本重复 **5 次**：全部通过；
- 仅做 patch 循环（worker pause，不调用 hook）**500 轮**：全部通过；
- live（4 worker 热循环、50 轮 install/uninstall）连续 5 次：**3 次完全通过，2 次在结束阶段目标以 SIGSEGV/-9 退出**（不是主线程调用挂起，发生在测试收尾/detach 前后）。因此主线程调用问题已修复，但“高频 live patch + teardown”仍有残余竞态。

### 残余限制

- **live patch 仍偶发结束阶段崩溃/挂起**（SIGSEGV 或未退出），即使换成简单常量 guard 也会出现 → 问题在 inline patch/STW 与 funchook 的交互，不在 VM/主线程；当前可用的稳定模式是**quiesced（目标线程暂停后再 patch）**；
- 线程列表由注入器在 attach 前快照，**补丁期间新建的线程不会被停**；需要周期性重新枚举或“先停住创建线程（clone hook）”；
- PC 落在补丁区域靠重试，极端热的小函数可能多次重试；
- 信号停车要求目标线程可被信号打断（长时间不可中断睡眠/屏蔽该信号会超时）；
- funchook 的 trampoline 在卸载后**故意不释放**（避免线程仍在 trampoline 中时被 free 成 SIGSEGV），会带来每次 patch 的少量内存泄漏；生产需做 trampoline 范围跟踪后再安全释放。

### 单次 live 安装/卸载验证（非高频）

用 `single_install.py` 模拟正常生产用法：4 个 worker 持续调用 → 安装一次 → 观察 50ms → 卸载一次 → 观察 50ms → 主线程调用确认恢复 105 → 退出；每个模式重复 20 个进程。

| 模式 | 结果 | 说明 |
|---|---|---|
| **BLOCK** | **17/20 成功** | 安装/生效/卸载/恢复均正确；3 次失败都是**进程退出阶段** SIGSEGV/SIGTRAP（-11/-5），不是 patch 逻辑错误 |
| **PASS** | **0/3 ~ 1/3 成功** | live 下 PASS 路径会崩溃；把 worker 暂停后 PASS 单次调用正常（返回 105 且原函数执行） |

结论：

- **单次 live BLOCK 补丁基本可用**，剩余问题是退出阶段崩溃（需要继续定位 detach/信号清理）；
- **PASS 路径在 live 多线程下不可用**（即使 1 个 worker 也常崩），怀疑 funchook 的 `real_target` trampoline 在并发调用/长跑下存在重入或重定位问题；quiesced 下正常。生产若需要 PASS 语义，必须换用自建 trampoline 或改用 plthook/preload。

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
