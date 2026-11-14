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

离线/签名：给 manifest 配置 `bundle_version`，用 `bundle.sign_bundle()` 生成 `.sig`，并在启动环境设置
`VULGATE_BUNDLE_KEY`，launcher 会在 `load_bundle` 阶段强制验签；`bundle_digest` 会写入安装回执与事件。
