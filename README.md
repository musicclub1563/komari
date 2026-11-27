# Komari (personal hardened fork)

[![Latest release](https://img.shields.io/github/v/release/musicclub1563/komari?display_name=tag&sort=semver)](https://github.com/musicclub1563/komari/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

[English](./README.md) | [简体中文](./README_zh-cn.md)

Komari is a lightweight, self-hosted server monitoring panel: a single Go binary serving a web UI, with metrics pushed by a small agent.

**This repository is a personal fork of [komari-monitor/komari](https://github.com/komari-monitor/komari).** It follows upstream `main` and, on top of it, keeps a security-hardening pass over the server, a reworked web-terminal and traffic-ledger subsystem, a reworked agent terminal, and a default theme built from this fork's frontend. The last few releases diverged far enough from upstream that the upstream README no longer describes what this build actually does — hence this document.

> [!NOTE]
> Looking for the vanilla project, its documentation and its community? Use [komari-monitor/komari](https://github.com/komari-monitor/komari) and [komari.wiki](https://www.komari.wiki/). This fork is maintained for personal deployments; it is not a supported distribution of the upstream project.

> [!WARNING]
> Komari is a self-hosted monitoring **and control** application: authenticated administrators can open shells, move files and run arbitrary SQL. Deploy it only on systems you own or are authorized to manage, keep the admin account behind strong credentials and 2FA, and do not expose it to the public internet without TLS and a reverse proxy you control. You are solely responsible for how you deploy and use it.

## What this fork changes

Everything below is already in the released binaries; the reasoning and verification for the server-side items are recorded in [`SECURITY_REVIEW_RESULTS.md`](./SECURITY_REVIEW_RESULTS.md).

| Area | Upstream | This fork |
| --- | --- | --- |
| Client IP resolution | gin default: trusts `X-Forwarded-For` from any peer | `trusted_proxies` is **empty by default**; forwarding headers are ignored unless the peer is explicitly trusted. Shared parser in `pkg/clientip`, override with `KOMARI_TRUSTED_PROXIES` |
| `admin:dbQuery` RPC | accepts any SQL statement | accepts a **single read-only** statement; write paths must use `admin:dbExec`; audit stores a redacted summary, never the raw statement or bound args |
| Plugin → RPC bridge | `server.call` may reach any registered method | privileged and sensitive methods are denied to plugins; `admin:*` calls are audited as `plugin:<name>` |
| Web terminal authorization | checked when the session is created | the credential used at attach time is re-validated every 5s; logout, session expiry or API-key rotation closes the session |
| Terminal writes (agent) | writes issued inline from the reader loop | a single PTY writer goroutine, idempotent `Close`, graceful shutdown budget, hard timeout on input |
| HTML rendering (theme) | raw `dangerouslySetInnerHTML` | every injection point goes through DOMPurify-based `<SafeHtml>` (footer, config blocks, notices, billing and chart tooltips) |
| SVG icons | inline injection after fetch | rendered through `<img>` with a source allowlist |
| Office preview | third-party preview iframe loaded automatically | explicit consent before a preview token is requested |
| PWA caching | caches `/api` responses | `NetworkOnly` for same-origin `/api/*` plus stale-cache cleanup on upgrade |
| 2FA enrollment | session cookie is enough to replace the secret | current TOTP code required when a secret is already enabled |
| Backup restore | restores into requested paths | entries validated to stay inside the data directory, atomic swap, failed restore leaves the old data untouched |
| Plugin update | old version deleted before the new one is unpacked | staged unpack with rollback on failure |
| `child_process` (jsruntime) | children can outlive the call | cancelled and reaped on timeout/limit, output ordering fixed |
| Build flags | default | `nomsgpack` + `sqlite_omit_load_extension` tags, `-Os -ffunction-sections -fdata-sections`, `-buildid=`, `--gc-sections,--strip-all` — noticeably smaller binaries |
| Default theme | upstream `komari-web` release | built from this fork's `komari-web` `radix` branch at a SHA pinned per release |

## Feature highlights

- **Realtime monitoring** — one-second metrics, history charts, group views, offline notifications.
- **Traffic ledger** — per-node billing cycle (anchor date + timezone), quota, manual correction and reset, with dashboard widgets.
- **Web terminal** — split panes, tabs, file manager with drag-select, upload progress, and reconnects that survive agent restarts.
- **Audit log** — terminal sessions, node edits, database statements and admin actions, with sensitive values redacted.
- **Themes and plugins** — theme market plus a JS plugin runtime with per-permission approval.
- **Modular dashboard** — draggable widgets (globe, billing, traffic quota, uptime, live bandwidth).

## Components and version pairing

| Repository | Role | Version line |
| --- | --- | --- |
| [`musicclub1563/komari`](https://github.com/musicclub1563/komari) | Server + bundled default theme (this repo) | `1.6.x`, mirrors upstream numbering |
| [`musicclub1563/komari-web`](https://github.com/musicclub1563/komari-web) | Default theme source (`radix` branch), pinned per release | no separate releases |
| [`musicclub1563/komari-agent`](https://github.com/musicclub1563/komari-agent) | Metrics agent and terminal bridge | `1.5.x` |

Pairing: server `>= 1.6.16` with agent `>= 1.5.18` gives terminal keepalive and reattach. Older agents keep working but will not reconnect on their own.

## Quick start

### Docker

```bash
docker run -d --name komari \
  -p 25774:25774 \
  -v "$PWD/data:/app/data" \
  -e KOMARI_TRUSTED_PROXIES="" \
  --restart unless-stopped \
  ghcr.io/musicclub1563/komari:latest
```

The container runs `komari server`, listens on `0.0.0.0:25774` and keeps everything it needs in `/app/data` (SQLite at `/app/data/komari.db`, backups at `/app/data/backup`). Set `KOMARI_TRUSTED_PROXIES` only when the container really sits behind a proxy you control.

### Binary

Download `komari-linux-amd64` (or the asset for your platform) from [Releases](https://github.com/musicclub1563/komari/releases), then:

```bash
chmod +x komari-linux-amd64
./komari-linux-amd64 server -l 0.0.0.0:25774 -d ./data/komari.db
```

Available assets: `linux` 386/amd64/arm64/loong64/riscv64 and `windows` 386/amd64/arm64.

### One-click install script

```bash
curl -fsSL https://raw.githubusercontent.com/musicclub1563/komari/main/install-komari.sh -o install-komari.sh
sudo bash install-komari.sh
```

The script is an interactive menu: install, upgrade (with backup), uninstall, and a standard / lite channel switch.

### Agent

Grab a token from the admin panel (node detail page), then on the monitored host:

```bash
wget -qO- https://raw.githubusercontent.com/musicclub1563/komari-agent/refs/heads/main/install.sh \
  | sudo bash -s -- -e https://monitor.example.com -t <token>
```

Docker and Windows variants are documented in the panel itself. The agent also supports `--auto-discovery` for zero-touch enrollment.

## Configuration essentials

| Item | Default | Notes |
| --- | --- | --- |
| `KOMARI_LISTEN` / `-l, --listen` | `0.0.0.0:25774` | HTTP listen address |
| `-d, --database` | `./data/komari.db` | SQLite file path |
| `KOMARI_TRUSTED_PROXIES` / `trusted_proxies` | empty | Comma-separated IP/CIDR of proxies. **Empty means every forwarding header is ignored** — see [`docs/trusted-proxies.md`](./docs/trusted-proxies.md) |
| Data directory | `./data` | Database, backups, uploaded themes |

## Upgrade notes

- **Behind a reverse proxy or CDN, set `trusted_proxies`.** With the default empty value, audit logs, sessions, terminal requests and plugin contexts record the proxy address instead of the real client.
- **Back up the database before upgrading.** The traffic ledger introduced new tables; migrations run on first start.
- **Historical traffic is not backfilled.** The ledger starts recording increments from the version that introduced it; older usage stays in the legacy statistics.
- **The default theme ships inside the binary.** Custom themes and plugins are unaffected by a server upgrade.

## Security

- Server-side review summary: [`SECURITY_REVIEW_RESULTS.md`](./SECURITY_REVIEW_RESULTS.md) — what was found, what was fixed, and what is explicitly left open (plugin signature verification, `dbExec` power, Windows `Process.Kill` scope).
- Proxy setup and migration guide: [`docs/trusted-proxies.md`](./docs/trusted-proxies.md).
- Plugin `child_process` semantics: [`pkg/jsruntime/README.md`](./pkg/jsruntime/README.md).
- To report a problem, open a private security advisory on this repository rather than a public issue.

## Build from source

Requirements: Go `1.26+` (toolchain `1.27.3`), `zig` for the release cross-build, Node `24` only if you want to rebuild the theme.

```bash
# server (development build)
go build ./...

# server (release flags: smaller binary, cgo sqlite)
CGO_ENABLED=1 CC="zig cc -target x86_64-linux-musl" \
  go build -trimpath -tags "nomsgpack sqlite_omit_load_extension" \
  -ldflags="-s -w -buildid= -extldflags=-Wl,--gc-sections,--strip-all" -o komari .
```

The default theme is packed into `web/public/defaultTheme/` (`dist.tar.zst` plus `komari-theme.json`). Releases build it from the pinned `komari-web` commit; to do it by hand:

```bash
git clone https://github.com/musicclub1563/komari-web && cd komari-web
npm ci && npm run build
tar -cf - -C dist . | zstd -19 -T0 -o ../komari/web/public/defaultTheme/dist.tar.zst
cp komari-theme.json ../komari/web/public/defaultTheme/
```

The exact steps (and the pinned SHA) live in [`.github/actions/build-frontend/action.yml`](./.github/actions/build-frontend/action.yml).

## Release process

1. Merge upstream into `main`, resolve conflicts in favour of this fork's hardening, run `go build ./...` and the terminal / RPC / traffic tests.
2. Bump `PINNED_REF` in `.github/actions/build-frontend/action.yml` to the new `komari-web` commit.
3. Tag `1.6.x` and publish a GitHub Release.
4. CI builds the frontend from that SHA, cross-compiles the eight platform binaries, pushes the Docker image, and attaches everything to the release.

Every push to `main` additionally publishes a `Snapshot-YYMMDDHHmm` prerelease, which is a convenient way to test a merge before tagging. Release notes are generated by a workflow and then curated by hand, so the published text is the authoritative one.

## Documentation and community

- Upstream documentation: <https://www.komari.wiki/>
- Upstream repository: <https://github.com/komari-monitor/komari>
- Theme and plugin ecosystem: upstream docs and theme market

## Credits and license

MIT licensed — see [`LICENSE`](./LICENSE). Third-party notices are in [`NOTICE`](./NOTICE).

Komari is designed and maintained upstream by the [komari-monitor](https://github.com/komari-monitor) team and its contributors; this fork only carries the divergences listed above. Thanks to everyone who reported the issues behind the hardening work.
