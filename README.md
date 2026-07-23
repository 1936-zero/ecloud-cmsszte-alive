# 公众移动云电脑 · 保活

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-可选-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![GitHub stars](https://img.shields.io/github/stars/1936-zero/ecloud-cmsszte-alive?style=social)](https://github.com/1936-zero/ecloud-cmsszte-alive)

> 关掉官方客户端后，云电脑容易被回收。本工具在你自己的电脑上登录账号、选桌面，用**协议心跳**把桌面顶住。  
> 适用于 **公众移动云电脑（ecloud）**：  
> - **CMSSZTE / ZTE / ZTEECLOUD**（中兴 / CMSS uSmartView）→ **Path B**（SPICE + oracle 心跳）  
> - **H3C 及其它非 CMSSZTE** → **HTTP** 桌面保活链路  
> **不支持** VMware Tools（vmtool）以及爱家账号。

你不需要会写代码。大多数情况下：**复制一段命令 → 按提示登录 → 选桌面 → 开始保活**。

仓库（本项目当前维护地址）：

```text
https://github.com/1936-zero/ecloud-cmsszte-alive.git
```

---

## 这个工具能做什么？

- 登录公众移动云电脑账号（支持短信验证码）
- 列出你名下的云电脑，**交互选择**要保活的那一台
- 需要时自动尝试开机，并准备连接
- 定时发送协议心跳，减少空闲回收
- **方式 A**：命令行保活
- **方式 B**：本机网页控制台（多账号多卡片，**不需要 Docker**）
- **方式 C**：Docker 一键网页版（本机可以不装 Python）

---

## 使用前需要准备什么？

| | 方式 A：命令行 | 方式 B：本机网页版 | 方式 C：Docker 网页版 |
|---|---|---|---|
| 适合谁 | 习惯终端、先跑通一台 | 想用浏览器、已装 Python | 想一键容器、少装环境 |
| 本机需要 | Git + Python 3.10+ | 同左 | [Docker](https://www.docker.com/products/docker-desktop/) |
| 打开方式 | 终端看日志 | 浏览器 `http://127.0.0.1:8080` | 浏览器 `http://127.0.0.1:8081` |

账号、密码、token **只保存在你自己电脑**上，不要发给别人，也不要提交到 Git。

下文命令统一写 **`python3`**。若系统提示找不到命令，可改成 `python`（安装 Python 时请勾选加入 PATH）。

---

## 一键安装并启动

> 已在项目目录时，可跳过 `git clone`，从安装依赖那一步开始。

### 方式 A：本机 Python 命令行（推荐先跑通）

#### Linux（Ubuntu / Debian / 云服务器）

复制**整段**到终端：

```bash
sudo apt update && sudo apt install -y git python3 python3-pip \
&& git clone https://github.com/1936-zero/ecloud-cmsszte-alive.git \
&& cd ecloud-cmsszte-alive \
&& pip3 install -r requirements.txt --user \
&& python3 main.py login \
&& python3 main.py list-desktops \
&& python3 main.py select-desktop \
&& python3 main.py setup \
&& python3 main.py desktop-keepalive
```

#### macOS

先安装 [Homebrew](https://brew.sh/)（若尚未安装），再执行：

```bash
brew install git python
git clone https://github.com/1936-zero/ecloud-cmsszte-alive.git
cd ecloud-cmsszte-alive
python3 -m pip install -r requirements.txt --user
python3 main.py login
python3 main.py list-desktops
python3 main.py select-desktop
python3 main.py setup
python3 main.py desktop-keepalive
```

#### Windows（PowerShell）

先安装 [Git](https://git-scm.com/download/win) 与 [Python 3.10+](https://www.python.org/downloads/)（勾选 **Add python.exe to PATH**）。

```powershell
git clone https://github.com/1936-zero/ecloud-cmsszte-alive.git
cd ecloud-cmsszte-alive
python3 -m pip install -r requirements.txt --user
python3 main.py login
python3 main.py list-desktops
python3 main.py select-desktop
python3 main.py setup
python3 main.py desktop-keepalive
```

若提示找不到 `python3`，把上面的 `python3` 全部换成 `python`。

**命令含义（按顺序）：**

1. `login`：账号、密码；若要短信，再输入**短信验证码**（不是用短信当密码）
2. `list-desktops` / `select-desktop`：看有几台、选一台（回车默认 0）
3. `setup`：需要时开机 + 准备连接（可选手动；见下）
4. `desktop-keepalive` / `keepalive`：前台保活（**默认内置先开机再分流**，一般不必再单独 `setup`）；停止按 `Ctrl+C`

**保活怎么走（CLI / WebUI 同序）：**

```text
login → 选桌面 → 开机(power first) → 按 origin 分流
  · CMSSZTE / ZTE / ZTEECLOUD → Path B
  · H3C / 其它非空 origin      → HTTP
  · --legacy-http 强制 HTTP；--force-path-b 强制 Path B；--no-power 跳过开机
```

Linux / macOS 也可用薄壳（与后两步等价）：

```bash
./bin/public-spice-keepalive setup
./bin/public-spice-keepalive run
```

**怎样算成功？** 终端持续有保活成功日志；手机/官方客户端里该桌面仍是运行中。

---

### 方式 B：本机网页版（不需要 Docker）

和方式 A 一样装好依赖后，用网页管理多账号：

#### Linux / macOS

```bash
git clone https://github.com/1936-zero/ecloud-cmsszte-alive.git
cd ecloud-cmsszte-alive
python3 -m pip install -r requirements.txt --user
python3 main.py web --host 127.0.0.1 --port 8080
```

浏览器打开：

```text
http://127.0.0.1:8080
```

#### Windows（PowerShell）

```powershell
git clone https://github.com/1936-zero/ecloud-cmsszte-alive.git
cd ecloud-cmsszte-alive
python3 -m pip install -r requirements.txt --user
python3 main.py web --host 127.0.0.1 --port 8080
```

浏览器打开：`http://127.0.0.1:8080`  
找不到 `python3` 时改用 `python`。

#### 网页里怎么操作

1. 登录（短信只填验证码）
2. 在卡片里选择云电脑
3. 点启动保活

> 关掉浏览器标签页后，若终端里的 `python3 main.py web` 还在跑，服务仍在；要停就在该终端按 `Ctrl+C`。  
> **不要**与方式 A 对**同一账号**同时保活（会互踢登录）。

---

### 方式 C：Docker 网页版（本机可不装 Python）

#### Linux / macOS

```bash
git clone https://github.com/1936-zero/ecloud-cmsszte-alive.git
cd ecloud-cmsszte-alive
docker compose up -d --build
```

浏览器打开：`http://127.0.0.1:8081`

#### Windows（PowerShell）

先安装并打开 [Docker Desktop](https://www.docker.com/products/docker-desktop/)，确认托盘里 Docker 已运行：

```powershell
git clone https://github.com/1936-zero/ecloud-cmsszte-alive.git
cd ecloud-cmsszte-alive
docker compose up -d --build
```

浏览器打开：`http://127.0.0.1:8081`

#### Docker 常用命令（三端相同）

```bash
# 看日志
docker compose logs -f

# 停止（账号数据在 ./data，不会丢）
docker compose down

# 更新代码后重建
git pull
docker compose up -d --build
```

**方式 C 注意（#75fixap 三端一致）：**

- 默认 `docker-compose.yml` 使用 **bridge 网络 + `ports: "8081:8081"`**，**Linux / Windows / macOS Docker Desktop 均可**。浏览器打开 `http://127.0.0.1:8081`。
- 容器内进程监听 `0.0.0.0:8081`（`web --host 0.0.0.0 --port 8081`）。若 8081 被占用：改 compose 的 `ports` / `command --port`，或先释放端口。
- **Linux 可选 host 网络**（CAG mint / Path B 更接近 CLI）：  
  `docker compose -f docker-compose.yml -f docker-compose.host.yml up -d --build`  
  Windows / macOS **不要**用 host override（Docker Desktop 上 host 网不等于 Linux host）。
- 默认挂载仓库内 **`./docker/stubs/installinfo.ini`**（空 `csap_id`），保证无官方客户端时也能启动 WebUI（HTTP-only；Path B mint 会失败并提示缺密钥）。  
  本机已装官方 CMSS 客户端、需要 Path B 时：  
  `INSTALLINFO_HOST=/path/to/real/installinfo.ini docker compose up -d`  
  （Linux 官方路径示例：`/opt/apps/com.cmss.saas.ecloudcomputer/files/drivers/CMSS/config/installinfo.ini`）
- 容器 `user: "1000:1000"`：请保证 `./data` 对该 uid 可写（`mkdir -p data && sudo chown -R 1000:1000 data`；Docker Desktop 上通常只需 `mkdir -p data`）。
- 打开页面若 **HTTP 500**：先 `docker compose logs -f`，常见是 data 权限或端口冲突。

---

## 一账号多台云电脑 / 多账号

| 你想做什么 | 命令行（方式 A） | 网页（方式 B / C） |
|------------|------------------|---------------------|
| 只保一台 | `select-desktop` → `desktop-keepalive`（内置开机+分流；可选 `setup`） | 一张卡选好桌面后启动 |
| 换成另一台 | 再 `select-desktop`，再保活 | 卡片里改选桌面 |
| 两台同时保 | **两个终端** + 两份配置（见下） | **多张账号卡**（推荐） |
| 多个账号 | 每个账号一份配置 + 独立终端 | 每账号一张卡 |

命令行第二台示例（Linux / macOS）：

```bash
export CLOUD_PC_CONFIG_FILE="$PWD/cloud_pc_desk2.json"
python3 main.py login
python3 main.py select-desktop
python3 main.py desktop-keepalive   # 或 keepalive；内置 power-first
```

Windows PowerShell：

```powershell
$env:CLOUD_PC_CONFIG_FILE = "$PWD\cloud_pc_desk2.json"
python3 main.py login
python3 main.py select-desktop
python3 main.py desktop-keepalive
```

---

## 常用命令一览

| 命令 | 作用 |
|------|------|
| `python3 main.py login` | 登录（含短信） |
| `python3 main.py list-desktops` | 列出云电脑 |
| `python3 main.py select-desktop` | 交互选择要保活的桌面 |
| `python3 main.py setup` | 开机（如需）+ 准备连接（可选；保活命令已内置 power-first） |
| `python3 main.py desktop-keepalive` | 前台保活：先开机 → 按 origin 走 Path B 或 HTTP |
| `python3 main.py keepalive` | 同上系入口（默认 Path B + oracle；可用 `--legacy-http`） |
| `python3 main.py web` | 本机网页控制台（默认 `0.0.0.0:8080`；Docker 方式 C 用 8081） |
| `./bin/public-spice-keepalive setup` | 同 `setup`（Linux / macOS） |
| `./bin/public-spice-keepalive run` | 同 `desktop-keepalive` |

---

## 可选：Linux 后台常驻（systemd）

仅在你**确认**要用系统服务时再装。示例单元在：

```text
packaging/systemd/ecloud-spice-keepalive.service.example
```

```bash
# 路径请改成你的真实项目目录后再启用
mkdir -p ~/.config/systemd/user
cp packaging/systemd/ecloud-spice-keepalive.service.example \
   ~/.config/systemd/user/ecloud-spice-keepalive.service
# 编辑 WorkingDirectory 等
systemctl --user daemon-reload
systemctl --user enable --now ecloud-spice-keepalive.service
systemctl --user status ecloud-spice-keepalive.service
```

停止：`systemctl --user stop ecloud-spice-keepalive.service`  
**注意：** 常驻与命令行 `desktop-keepalive` 是同一套保活逻辑，**不要**对同一桌面同时开两套。

---

## 配置文件（自动生成，勿外传）

| 文件 | 作用 |
|------|------|
| `cloud_pc.json` | 账号、token、选中的桌面（建议 `chmod 600`） |
| `./data/`（Docker） | 容器内账号与状态 |

---

## 保活在干什么（白话）

1. 登录拿 token  
2. 选桌面 → **先开机**（`operate=available`，已开机则跳过）  
3. 看桌面 `originCompanyCode` 分流：  
   - CMSSZTE / ZTE / ZTEECLOUD → Path B 协议心跳 + 状态核对  
   - H3C 等 → HTTP 桌面保活  
4. 按固定间隔重复，降低「空闲被回收」的概率  

不能替代官方客户端里的远程桌面操作；只是尽量让桌面别被系统收回。

---

## 安全与声明

- 不要把 `cloud_pc.json`、日志、截图里的 token 发给陌生人  
- 不要把配置提交到公开 Git 仓库  
- 请遵守云电脑服务条款与当地法规；本工具为自用/研究辅助，不提供未授权访问或绕过计费的用途  

---

## 目录（客户视角）

```text
.
├── main.py                      # 命令入口
├── bin/public-spice-keepalive   # Linux/macOS 可选薄壳
├── web/                         # 网页控制台
├── docker-compose.yml           # 方式 C
├── requirements.txt
├── packaging/systemd/           # 可选常驻
└── data/                        # Docker 数据（运行后生成）
```

---

## 开源协议

本项目采用 **[MIT License](LICENSE)**。

---

## 社区与支持

### 🚩 友情链接

感谢 **LinuxDo** 社区的支持！

[![LinuxDo](https://img.shields.io/badge/社区-LinuxDo-blue?style=for-the-badge)](https://linux.do/)
