# Komari（个人加固分支）

[![最新版本](https://img.shields.io/github/v/release/musicclub1563/komari?display_name=tag&sort=semver)](https://github.com/musicclub1563/komari/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

[English](./README.md) | [简体中文](./README_zh-cn.md)

Komari 是一款轻量级的自托管服务器监控面板：单个 Go 二进制提供 Web 界面，被监控机器通过一个轻量 Agent 上报数据。

**本仓库是 [komari-monitor/komari](https://github.com/komari-monitor/komari) 的个人分支。** 它持续合并上游 `main`，并在此之上保留了一套服务端安全加固、重写过的网页终端与流量台账子系统、重写过的 Agent 终端，以及由本分支前端构建的默认主题。近几个版本与上游的差异已经大到上游 README 无法准确描述本版本的行为，因此单独写了这份说明。

> [!NOTE]
> 想用原版、查官方文档或参与社区，请前往 [komari-monitor/komari](https://github.com/komari-monitor/komari) 与 [komari.wiki](https://www.komari.wiki/)。本分支面向个人部署维护，不是上游的官方发行版。

> [!WARNING]
> Komari 是自托管的监控**兼控制**程序：管理员通过它可以开 shell、传文件、执行任意 SQL。请只部署在你拥有或已获授权管理的系统上，管理员账号务必使用强密码并启用两步验证；不要把面板直接暴露在公网，至少要有自己可控的 TLS 与反向代理。部署与使用方式及其后果由使用者自行负责。

## 与上游的差异

以下内容都已包含在发布的二进制中；服务端改动的原因与验证记录见 [`SECURITY_REVIEW_RESULTS.md`](./SECURITY_REVIEW_RESULTS.md)。

| 方面 | 上游 | 本分支 |
| --- | --- | --- |
| 客户端 IP 解析 | gin 默认信任任意来源的 `X-Forwarded-For` | `trusted_proxies` **默认空**，只有对端在可信列表内才读转发头；解析逻辑收敛到 `pkg/clientip`，可用 `KOMARI_TRUSTED_PROXIES` 覆盖 |
| `admin:dbQuery` RPC | 接受任意 SQL | 只接受**单条只读**语句，写操作必须走 `admin:dbExec`；审计只记录脱敏摘要，不落原始语句与绑定参数 |
| 插件调用 RPC | `server.call` 可触达任意已注册方法 | 特权方法与敏感方法对插件一律拒绝；`admin:*` 调用按 `plugin:<名称>` 记审计 |
| 网页终端授权 | 建立会话时校验一次 | 附着时的凭据每 5 秒复核一次；登出、会话过期或 API Key 轮换会直接关闭会话 |
| 终端写入（Agent） | 读循环内直接写 PTY | 单一写入协程、幂等 `Close`、有预算的优雅退出与输入写超时 |
| 主题 HTML 渲染 | 直接 `dangerouslySetInnerHTML` | 所有注入点统一走基于 DOMPurify 的 `<SafeHtml>`（页脚、配置块、通知、资费与图表提示） |
| SVG 图标 | 拉取后内联注入 | 以 `<img>` 渲染并限制来源白名单 |
| Office 预览 | 自动加载第三方预览 iframe | 必须显式确认后才申请预览令牌 |
| PWA 缓存 | 缓存 `/api` 响应 | 同源 `/api/*` 使用 `NetworkOnly`，升级时清理旧缓存 |
| 两步验证绑定 | 有会话即可覆盖密钥 | 已启用时替换密钥必须提供当前 TOTP |
| 备份恢复 | 按请求路径写回 | 校验条目必须落在数据目录内、原子切换，失败时旧数据不受影响 |
| 插件更新 | 先删除旧版本再解压 | 暂存解压，失败自动回滚 |
| `child_process`（jsruntime） | 子进程可能活过调用 | 超时或超限时取消并回收，修正输出顺序 |
| 构建参数 | 默认 | `nomsgpack` + `sqlite_omit_load_extension` 标签、`-Os -ffunction-sections -fdata-sections`、`-buildid=`、`--gc-sections,--strip-all`，二进制明显更小 |
| 默认主题 | 上游 `komari-web` 发行版 | 由本分支 `komari-web` 的 `radix` 分支构建，每个版本固定到一个提交 |

## 功能特性

- **实时监控**：秒级数据、历史图表、分组视图、离线通知。
- **流量台账**：按节点配置计费周期（锚定日 + 时区）、配额，支持人工校正与重置，并提供仪表盘组件。
- **网页终端**：分屏、多标签、文件管理器（支持拖拽框选）、上传进度，Agent 重启后可重连恢复。
- **审计日志**：终端会话、节点编辑、数据库语句与后台操作，敏感内容脱敏。
- **主题与插件**：主题市场，以及按权限逐项授权的 JS 插件运行时。
- **模块化仪表盘**：可自由布局的小组件（地球、账单、流量配额、在线率、实时带宽）。

## 组件与版本配套

| 仓库 | 作用 | 版本线 |
| --- | --- | --- |
| [`musicclub1563/komari`](https://github.com/musicclub1563/komari) | 服务端 + 内置默认主题（本仓库） | `1.6.x`，跟随上游编号 |
| [`musicclub1563/komari-web`](https://github.com/musicclub1563/komari-web) | 默认主题源码（`radix` 分支），按版本固定提交 | 不单独发版 |
| [`musicclub1563/komari-agent`](https://github.com/musicclub1563/komari-agent) | 数据采集与终端桥接 Agent | `1.5.x` |

配套建议：服务端 `>= 1.6.16` 搭配 Agent `>= 1.5.18` 才有终端保活与断线重连；旧版 Agent 仍可正常使用，但不会自动重连。

## 快速开始

### Docker

```bash
docker run -d --name komari \
  -p 25774:25774 \
  -v "$PWD/data:/app/data" \
  -e KOMARI_TRUSTED_PROXIES="" \
  --restart unless-stopped \
  ghcr.io/musicclub1563/komari:latest
```

容器执行 `komari server`，监听 `0.0.0.0:25774`，数据都在 `/app/data`（SQLite 为 `/app/data/komari.db`，备份在 `/app/data/backup`）。只有确实位于自己可控的代理之后，才需要设置 `KOMARI_TRUSTED_PROXIES`。

### 二进制

从 [Releases](https://github.com/musicclub1563/komari/releases) 下载对应产物，然后：

```bash
chmod +x komari-linux-amd64
./komari-linux-amd64 server -l 0.0.0.0:25774 -d ./data/komari.db
```

产物覆盖 `linux` 386/amd64/arm64/loong64/riscv64 与 `windows` 386/amd64/arm64。

### 一键脚本

```bash
curl -fsSL https://raw.githubusercontent.com/musicclub1563/komari/main/install-komari.sh -o install-komari.sh
sudo bash install-komari.sh
```

脚本是交互式菜单：安装、升级（自动备份）、卸载，以及标准版 / 精简版通道切换。

### Agent

先在后台节点详情页拿到 Token，然后在被监控机器上执行：

```bash
wget -qO- https://raw.githubusercontent.com/musicclub1563/komari-agent/refs/heads/main/install.sh \
  | sudo bash -s -- -e https://monitor.example.com -t <token>
```

Docker 与 Windows 的安装方式在面板里直接生成；也支持 `--auto-discovery` 免手填的方式。

## 关键配置

| 项目 | 默认值 | 说明 |
| --- | --- | --- |
| `KOMARI_LISTEN` / `-l, --listen` | `0.0.0.0:25774` | HTTP 监听地址 |
| `-d, --database` | `./data/komari.db` | SQLite 文件路径 |
| `KOMARI_TRUSTED_PROXIES` / `trusted_proxies` | 空 | 可信代理的 IP/CIDR，逗号分隔。**为空表示完全忽略转发头**，详见 [`docs/trusted-proxies.md`](./docs/trusted-proxies.md) |
| 数据目录 | `./data` | 数据库、备份、上传的主题 |

## 升级须知

- **反向代理或 CDN 后面部署一定要配置 `trusted_proxies`。** 默认空值时，审计日志、登录会话、终端请求与插件上下文记录的都是代理地址。
- **升级前先备份数据库。** 流量台账引入了新表，首次启动会自动迁移。
- **历史流量不会回填。** 台账从引入该功能的版本开始记录增量，更早的用量仍按原有统计展示。
- **默认主题打包在二进制里。** 升级服务端不会影响自定义主题与插件。

## 安全

- 服务端复核摘要：[`SECURITY_REVIEW_RESULTS.md`](./SECURITY_REVIEW_RESULTS.md)，包含已修复项、验证结果与明确保留的残余风险（插件签名、`dbExec` 权限、Windows 下 `Process.Kill` 的覆盖范围）。
- 代理配置与迁移：[`docs/trusted-proxies.md`](./docs/trusted-proxies.md)。
- 插件 `child_process` 语义：[`pkg/jsruntime/README.md`](./pkg/jsruntime/README.md)。
- 发现问题请在本仓库提交私密安全公告，不要直接开公开 issue。

## 从源码构建

依赖：Go `1.26+`（toolchain `1.27.3`），发布交叉编译需要 `zig`，只有重建主题时才需要 Node `24`。

```bash
# 服务端（开发构建）
go build ./...

# 服务端（发布参数：更小的二进制 + cgo sqlite）
CGO_ENABLED=1 CC="zig cc -target x86_64-linux-musl" \
  go build -trimpath -tags "nomsgpack sqlite_omit_load_extension" \
  -ldflags="-s -w -buildid= -extldflags=-Wl,--gc-sections,--strip-all" -o komari .
```

默认主题被打包进 `web/public/defaultTheme/`（`dist.tar.zst` 与 `komari-theme.json`）。正式发布时由 CI 按固定提交构建；手工构建步骤如下：

```bash
git clone https://github.com/musicclub1563/komari-web && cd komari-web
npm ci && npm run build
tar -cf - -C dist . | zstd -19 -T0 -o ../komari/web/public/defaultTheme/dist.tar.zst
cp komari-theme.json ../komari/web/public/defaultTheme/
```

完整步骤（含固定的提交 SHA）见 [`.github/actions/build-frontend/action.yml`](./.github/actions/build-frontend/action.yml)。

## 发版流程

1. 合并上游到 `main`，冲突以本分支的加固实现为准，跑 `go build ./...` 以及终端 / RPC / 流量相关测试。
2. 把 `.github/actions/build-frontend/action.yml` 里的 `PINNED_REF` 更新到新的 `komari-web` 提交。
3. 打 `1.6.x` 标签并发布 GitHub Release。
4. CI 按该提交构建前端、交叉编译 8 个平台二进制、推送 Docker 镜像并附到 Release。

每次推送到 `main` 还会额外发布 `Snapshot-YYMMDDHHmm` 预发布包，适合在打标签前先验证一次合并。Release 正文由工作流生成后人工校对，以最终发布的文本为准。

## 文档与社区

- 上游文档：<https://www.komari.wiki/>
- 上游仓库：<https://github.com/komari-monitor/komari>
- 主题与插件生态：见上游文档与主题市场

## 致谢与许可

MIT 许可，见 [`LICENSE`](./LICENSE)；第三方声明见 [`NOTICE`](./NOTICE)。

Komari 由 [komari-monitor](https://github.com/komari-monitor) 团队与社区设计维护，本分支只承载上面列出的差异。感谢所有报告问题、帮助定位加固项的朋友。
