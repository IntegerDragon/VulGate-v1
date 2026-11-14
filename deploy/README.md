# 部署示例

`vulgate-frida.service` 是一个 systemd 单元示例：

- `ExecStart` 用 `run.py --spawn` 托管启动目标，因此 Yama `ptrace_scope=1` 下不需要 root；
- 只授予 `CAP_SYS_PTRACE`，并设置 `NoNewPrivileges=true`；
- `--control-socket` 暴露 `cli.py status/metrics/uninstall` 控制通道；
- `--events` 输出统一 JSONL 事件流，便于审计与采集。

安装步骤（示例）：

```sh
install -d /opt/vulgate /etc/vulgate/patch /var/log/vulgate
cp -r build/frida-linux/* /opt/vulgate/          # agent.js/run.py/bundle.py/...
install -m 0644 my.manifest.json /etc/vulgate/patch/manifest.json
install -m 0644 my.actions.json  /etc/vulgate/patch/actions.json
install -m 0644 deploy/vulgate-frida.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vulgate-frida
```

容器内运行：目标与 launcher 必须在同一 PID namespace，并添加 `--cap-add=SYS_PTRACE`；
若镜像的 seccomp 仍拒绝 ptrace，可再加 `--security-opt seccomp=unconfined`（Frida 版本差异）。

## 多线程目标：LD_PRELOAD 模式

Frida attach 路径不支持非主线程门控。对可符号插入的动态链接目标改用原生库：

```sh
python -m runtime.preload.build --manifest /etc/vulgate/patch/manifest.json \
    --catalog /etc/vulgate/patch/actions.json --output /opt/vulgate/libvgpreload.so
LD_PRELOAD=/opt/vulgate/libvgpreload.so /usr/sbin/target ...
```

限制：只覆盖经过动态符号表（PLT）的调用；观察/map 暂不支持；静态链接目标不适用。4 线程压测见 `tests/test_preload.py`。

离线/签名：给 manifest 配置 `bundle_version`，用 `bundle.sign_bundle()` 生成 `.sig`，并在启动环境设置
`VULGATE_BUNDLE_KEY`，launcher 会在 `load_bundle` 阶段强制验签；`bundle_digest` 会写入安装回执与事件。
