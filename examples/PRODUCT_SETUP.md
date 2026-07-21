# 产品 setup 说明

面向**公众移动云电脑**。默认主路径为 SPICE Path B 心跳；不要求安装官方客户端界面。

## 最短路径

```bash
python3 main.py login
./bin/public-spice-keepalive setup
./bin/public-spice-keepalive run
```

可选：setup 后立刻 1 轮自检：

```bash
./bin/public-spice-keepalive setup --with-path-b
```

## 流程说明

1. 登录 → `access_token` 写入本地 `cloud_pc.json`
2. 列桌面 → 选择目标机
3. **仅首次**调用开机（`power_on_done` 记入配置后，后续保活不再开机）
4. 签发 connectStr 到本地 plain 文件（日志只记路径）
5. Path B 使用内置 `assets/templates/{pre,post}` 跑心跳

## 网关配置优先级

1. CLI：`--host` / `--cag-port` / `--csapip`
2. 环境变量：`CAG_HOST` `CAG_PORT` `CSAPIP` / `ECLOUD_CSAPIP`
3. `cloud_pc.json` 中的字段
4. 本机客户端配置探测（可选，不强制安装）
5. 内置默认值（不同客户环境请用上面方式覆盖）

## 开机门闩

| 行为 | 参数 |
|------|------|
| 已开过则跳过 | 默认（看 `power_on_done`） |
| 强制再开一次 | `--force-power`（含 SaaS 已 running 仍 re-operate） |
| 完全跳过开机 | `--no-power` |
| 开机后等待 | `--power-wait N`（默认 **15s**，env `CLOUD_PC_POWER_WAIT`） |

### mint 501 / no_connectStr 自动恢复（#75fixw）

SaaS 报 `already_running` 时首次会**跳过** `operate=available`，但 CAG 仍可能签不出 connectStr（`result=501 no_connectStr`）。

**CLI 与 WebUI 共用** `run_product_setup` 恢复链（仅一次）：

1. 首次 mint 失败且错误可恢复（`501` / `no_connectStr`）
2. **force** `ensure_powered_once`（绕过 `already_running` + `power_on_done`）
3. 等待 `--power-wait`（默认 15s）
4. **再 mint 一次**

| 行为 | 参数 |
|------|------|
| 启用恢复（默认） | 无（`mint_power_retry=True`） |
| 关闭恢复 | `--no-mint-power-retry` |

日常 Path B 保活轮次仍**不再开机**（`power_on_done` 门闩不变）。

## 离线自检

```bash
python3 main.py setup --selfcheck
```

## 安全

- 不要把 `cloud_pc.json`、plain、token 提交到 git 或发给他人
- 日志保持 path-only
- 未完成双证据前，不声明生产级 dual

## 非目标

- 静默安装官方客户端
- 用浏览器 CDP 自动捞串作为主路径
