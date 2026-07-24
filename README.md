# 公众移动云电脑 · 保活

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-可选-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![GitHub stars](https://img.shields.io/github/stars/1936-zero/ecloud-cmsszte-alive?style=social)](https://github.com/1936-zero/ecloud-cmsszte-alive)

> 云电脑空闲一段时间容易被系统回收。本工具在你自己的电脑上登录账号、选桌面，按厂商走两条保活链路之一，把桌面顶住。  
> 适用于 **公众移动云电脑（ecloud）**：  
> - **CMSSZTE / ZTE / ZTEECLOUD**（中兴 / CMSS uSmartView）→ **Path B**（协议心跳 + 状态核对）  
> - **H3C 及其它非 CMSSZTE** → **HTTP** 桌面保活链路  
> **不支持** VMware Tools（vmtool）以及爱家账号。本工具只做保活，不提供远程桌面画面操作。

你不需要会写代码。大多数情况下：**先装环境 → 逐条运行命令 → 按提示输入账号/密码/验证码 → 选桌面 → 开始保活**（登录步骤不能「无交互一键粘贴」）。

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
| 打开方式 | 终端看日志 | 浏览器 `http://127.0.0.1:8081` | 浏览器 `http://127.0.0.1:8081` |
| 网络说明 | 本机进程 | 本机进程 | **Linux：默认 host 容器**；**Win/mac Desktop：须 bridge 覆盖**（见方式 C） |

账号、密码、token **只保存在你自己电脑**上，不要发给别人，也不要提交到 Git。

下文命令统一写 **`python3`**。若系统提示找不到命令，可改成 `python`（安装 Python 时请勾选加入 PATH）。

---

## 安装并启动

> 已在项目目录时，可跳过 `git clone`，从安装依赖那一步开始。  
> **重要**：`login` / `select-desktop` 是**交互命令**，会在终端里提示你输入**账号、密码、短信验证码**（以及选桌面编号）。  
> **不要**把安装命令和登录命令用 `&&` 拼成「一键粘贴」——装完依赖后，**逐条**执行下面「登录与保活」的命令，停在提示符时按屏幕输入即可。

### 方式 A：本机 Python 命令行（推荐先跑通）

#### Linux（Ubuntu / Debian / 云服务器）

**① 安装（可复制整段；无交互）：**

```bash
sudo apt update && sudo apt install -y git python3 python3-pip python3-venv
git clone https://github.com/1936-zero/ecloud-cmsszte-alive.git
cd ecloud-cmsszte-alive
# Debian/Ubuntu 12+ 常开 PEP 668：不要用系统 pip 直装，用 venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -r requirements.txt
```

> 若仍坚持用户目录安装：`python3 -m pip install -r requirements.txt --user`；若报 `externally-managed-environment`，**必须**走上面 venv，不要 `sudo pip`。

**② 登录与保活（逐条执行；需键盘输入）：**

```bash
cd ecloud-cmsszte-alive   # 若尚未进入目录
python3 main.py login              # 提示 account / password；要短信时再输入验证码（半角数字）
python3 main.py list-desktops      # 可选：先看有几台
python3 main.py select-desktop     # 交互选桌面（回车默认 0）
python3 main.py desktop-keepalive  # 前台保活；停止按 Ctrl+C
```

> 可选：`python3 main.py setup` 可单独做开机+准备连接；**一般不必**——`desktop-keepalive` 已内置 power-first。

#### macOS

先安装 [Homebrew](https://brew.sh/)（若尚未安装）。

**① 安装：**

```bash
brew install git python
git clone https://github.com/1936-zero/ecloud-cmsszte-alive.git
cd ecloud-cmsszte-alive
python3 -m pip install -r requirements.txt --user
```

**② 登录与保活（逐条执行）：**

```bash
python3 main.py login
python3 main.py list-desktops      # 可选
python3 main.py select-desktop
python3 main.py desktop-keepalive
```

#### Windows（PowerShell）

先安装 [Git](https://git-scm.com/download/win) 与 [Python 3.10+](https://www.python.org/downloads/)（勾选 **Add python.exe to PATH**）。

**① 安装：**

```powershell
git clone https://github.com/1936-zero/ecloud-cmsszte-alive.git
cd ecloud-cmsszte-alive
python -m pip install -r requirements.txt --user
```

**② 登录与保活（逐条执行）：**

```powershell
python main.py login
python main.py list-desktops      # 可选
python main.py select-desktop
python main.py desktop-keepalive
```

若本机只有 `python3` 命令，把上面的 `python` 全部换成 `python3`。

**Windows 路径说明（issue #1）：**
- 会话凭证默认写在系统临时目录：`%TEMP%\ecloud-pathb\connectstr.plain`（**不是** Linux 的 `/tmp/...`，也不是 `C:\tmp\...`）。
- Path B 帧模板默认用仓库内 `assets\templates\pre` 与 `assets\templates\post`（clone 即有，无需手动准备）。
- `desktop-keepalive` / `keepalive` 在凭证文件缺失时会**自动 mint**（与 WebUI 同序：开机 → 签发 → Path B）；也可先跑 `python main.py setup`。
- 如需自定义凭证路径：`$env:SHORT_CONNECT_PLAIN_FILE="D:\path\connectstr.plain"` 或 `python main.py desktop-keepalive --plain D:\path\connectstr.plain`。

**命令含义（按顺序）：**

1. `login`：终端交互——账号、密码；若要短信，再输入**短信验证码**（不是用短信当密码；半角数字）
2. `list-desktops` / `select-desktop`：看有几台、选一台（回车默认 0）
3. `setup`：**可选**；需要时开机 + 准备连接（保活命令已内置 power-first + 缺凭证自动 mint，多数情况可跳过）
4. `desktop-keepalive` / `keepalive`：前台保活；停止按 `Ctrl+C`

**保活怎么走（CLI / WebUI 同序）：**

```text
login → 选桌面 → 开机(power first) → 按 origin 分流
  · CMSSZTE / ZTE / ZTEECLOUD → Path B
  · H3C / 其它非空 origin      → HTTP
  · --legacy-http 强制 HTTP；--force-path-b 强制 Path B；--no-power 跳过开机
```

**Path B 密钥文件（方式 A / B 本机）：** 仓库已带  
`data/config/installinfo.ini`（产品 `PublicKey.csap_id`，**不是账号密码**）。  
clone 后即可用，**不必**从桌面客户端复制。也可设 `INSTALLINFO_PATH=...` 覆盖。

Linux / macOS 也可用薄壳（与后两步等价）：

```bash
./bin/public-spice-keepalive setup
./bin/public-spice-keepalive run
```

**怎样算成功？** 终端持续有保活成功日志；手机 App / 云电脑控制台里该桌面仍是运行中。

---

### 方式 B：本机网页版（不需要 Docker）

和方式 A 一样装好依赖后，用网页管理多账号：

#### Linux / macOS

```bash
git clone https://github.com/1936-zero/ecloud-cmsszte-alive.git
cd ecloud-cmsszte-alive
python3 -m pip install -r requirements.txt --user
python3 main.py web --host 127.0.0.1 --port 8081
```

浏览器打开：

```text
http://127.0.0.1:8081
```

#### Windows（PowerShell）

```powershell
git clone https://github.com/1936-zero/ecloud-cmsszte-alive.git
cd ecloud-cmsszte-alive
python3 -m pip install -r requirements.txt --user
python3 main.py web --host 127.0.0.1 --port 8081
```

浏览器打开：`http://127.0.0.1:8081`  
找不到 `python3` 时改用 `python`。

#### 网页里怎么操作

1. 登录（短信只填验证码）
2. 在卡片里选择云电脑
3. 点启动保活

> 关掉浏览器标签页后，若终端里的 `python3 main.py web` 还在跑，服务仍在；要停就在该终端按 `Ctrl+C`。  
> **不要**与方式 A 对**同一账号**同时保活（会互踢登录）。

---

### 方式 C：Docker 网页版（本机可不装 Python）

> **命令按系统二选一，不要混用：**  
> - **Linux** → 只用 `docker compose …`（**默认 host 网络容器**，适合 Path B）  
> - **Windows / macOS Docker Desktop** → **必须**每次都加  
>   `-f docker-compose.yml -f docker-compose.bridge.yml`（**bridge 覆盖**；Desktop 的 host ≠ Linux host）

#### Linux：host 网络容器（默认，推荐）

```bash
git clone https://github.com/1936-zero/ecloud-cmsszte-alive.git
cd ecloud-cmsszte-alive
docker compose up -d --build
```

浏览器打开：`http://127.0.0.1:8081`

> 默认 **`network_mode: host`** + 命名卷 **`ecloud_data`**（一般不用 `chown`）。  
> Path B / CAG `:8899` mint 与本机同路由。WebUI 直接占宿主机 **8081**。容器 uid 1000。

**Linux 日常命令：**

```bash
docker compose logs -f
docker compose down          # 停容器；勿加 -v（-v 会删命名卷、清空账号）
git pull
docker compose up -d --build
# 强制按新 compose 重建（例如刚改网络模式后）
docker compose up -d --force-recreate
```

#### Windows / macOS：Docker Desktop + bridge 覆盖（必加）

Docker Desktop **没有**与 Linux 等价的 host 网络，**不要**只跑 `docker compose up`（那会按默认 host，在 Desktop 上无效/异常）。  
请**始终**带上 bridge 覆盖文件：

**macOS / Windows（Git Bash、WSL 内 Docker 若走 Desktop 引擎时同理）：**

```bash
git clone https://github.com/1936-zero/ecloud-cmsszte-alive.git
cd ecloud-cmsszte-alive
docker compose -f docker-compose.yml -f docker-compose.bridge.yml up -d --build
```

**Windows PowerShell：**

```powershell
git clone https://github.com/1936-zero/ecloud-cmsszte-alive.git
cd ecloud-cmsszte-alive
docker compose -f docker-compose.yml -f docker-compose.bridge.yml up -d --build
```

浏览器打开：`http://127.0.0.1:8081`（bridge 映射 `8081:8081`）

**Win / mac 日常命令（同样必须带两个 `-f`）：**

```bash
docker compose -f docker-compose.yml -f docker-compose.bridge.yml logs -f
docker compose -f docker-compose.yml -f docker-compose.bridge.yml down
git pull
docker compose -f docker-compose.yml -f docker-compose.bridge.yml up -d --build
docker compose -f docker-compose.yml -f docker-compose.bridge.yml up -d --force-recreate
```

> bridge 下 Path B 若出现 `ReadTimeout … :8899`：可加大 `CLOUD_PC_MINT_TIMEOUT` 后重建；仍不稳请改用 **方式 B（本机 Python 网页）** 或 **方式 A**，不要用 Desktop「假 host」硬顶。

#### 备份 / 恢复账号（Linux 与 Win/mac 相同）

```bash
# 备份到当前目录 data-backup/
docker compose cp ecloud-cmsszte-alive:/app/data ./data-backup

# 恢复（容器已 up）
docker compose cp ./data-backup/. ecloud-cmsszte-alive:/app/data
```

> Win/mac 若 `docker compose cp` 报项目名歧义，在命令前同样加上  
> `-f docker-compose.yml -f docker-compose.bridge.yml`。

#### 可选：绑定宿主机 `./data`（开发 / 要直接摸文件）

默认命名卷即可。需要仓库旁可见目录、或与本机 CLI 共用配置时：

**Linux（host + bind）：**

```bash
mkdir -p data
# 仅当目录对 uid 1000 不可写时（例如曾用 root 建过）
sudo chown -R 1000:1000 data
docker compose -f docker-compose.yml -f docker-compose.bind.yml up -d --build
```

**Win / mac（bridge + bind，两个覆盖都要）：**

```bash
mkdir -p data
docker compose -f docker-compose.yml -f docker-compose.bridge.yml -f docker-compose.bind.yml up -d --build
```

#### 从旧版 `./data` bind 迁到命名卷

```bash
# Linux
docker compose up -d --build
docker compose cp ./data/. ecloud-cmsszte-alive:/app/data
docker compose restart

# Win / mac：up 时带 bridge
# docker compose -f docker-compose.yml -f docker-compose.bridge.yml up -d --build
# docker compose -f docker-compose.yml -f docker-compose.bridge.yml cp ./data/. ecloud-cmsszte-alive:/app/data
# docker compose -f docker-compose.yml -f docker-compose.bridge.yml restart
```

**方式 C 注意：**

- **Linux 默认**：`docker-compose.yml` = **`network_mode: host` + 命名卷 `ecloud_data`**。WebUI：`http://127.0.0.1:8081`（无 `ports:` 映射）。
- **Windows / macOS Docker Desktop 默认命令必须是：**  
  `docker compose -f docker-compose.yml -f docker-compose.bridge.yml up -d --build`  
  （bridge + `8081:8081`）。**不要**指望 Desktop 上的 host。
- Linux 若故意要 bridge（隔离 / 多实例端口映射）：也可加 `docker-compose.bridge.yml`；CAG mint 变慢或 `ReadTimeout :8899` 时改回**不带** bridge 的默认 host。
- 宿主机 **8081 被占用**：host 模式改 `command` 的 `--port` 或释放端口（改 `ports:` 无效）；bridge 模式可改 `docker-compose.bridge.yml` 里的 `ports`。
- **方式 C = Docker 起 WebUI，Path B 或 HTTP 保活**（不依赖官方桌面客户端）。
- 默认挂载 **`./docker/stubs/installinfo.ini`**（与仓库 **`data/config/installinfo.ini`** 同密钥；产品 `PublicKey.csap_id`，**不是账号密码**）。覆盖：  
  `INSTALLINFO_HOST=/path/to/installinfo.ini docker compose up -d`
- **`docker compose down -v` 会删除命名卷 `ecloud_data`（账号清空）**；日常停服用 `down`（不要 `-v`）。
- 打开页面若 **HTTP 500**：先看日志；优先查端口冲突 / 构建失败；仅 bind 模式再查 `./data` 权限。
- 旧文件 `docker-compose.host.yml` 为兼容 no-op（默认已是 host），**不必**再 `-f` 它。

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
| `python3 main.py web` | 本机网页控制台（默认 `0.0.0.0:8081`，与 Docker 方式 C 一致） |
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
| Docker 命名卷 `ecloud_data` | 方式 C 默认账号与状态（备份见上 `docker compose cp`） |
| `./data/`（可选 bind） | 仅使用 `docker-compose.bind.yml` 时出现在仓库旁 |

---

## 保活在干什么（白话）

1. 登录拿 token  
2. 选桌面 → **先开机**（`operate=available`，已开机则跳过）  
3. 看桌面 `originCompanyCode` 分流：  
   - CMSSZTE / ZTE / ZTEECLOUD → Path B 协议心跳 + 状态核对  
   - H3C 等 → HTTP 桌面保活  
4. 按固定间隔重复，降低「空闲被回收」的概率  

本工具**不是**远程桌面软件，不会投屏/键鼠进云电脑；两条链路（Path B / HTTP）只负责定时心跳，尽量让桌面别被系统空闲回收。

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
├── docker-compose.yml           # 方式 C 默认：host 网络 + 命名卷 ecloud_data
├── docker-compose.bridge.yml    # 可选：Win/mac Desktop 或 Linux bridge
├── docker-compose.bind.yml      # 可选：绑 ./data
├── docker-compose.host.yml      # 兼容旧脚本（no-op，默认已是 host）
├── requirements.txt
├── packaging/systemd/           # 可选常驻
└── data/                        # 仅 bind 模式或本机 CLI 使用
```

---

## 开源协议

本项目采用 **[MIT License](LICENSE)**。

---

## 社区与支持

### 🚩 友情链接

感谢 **LinuxDo** 社区的支持！

[![LinuxDo](https://img.shields.io/badge/社区-LinuxDo-blue?style=for-the-badge)](https://linux.do/)
