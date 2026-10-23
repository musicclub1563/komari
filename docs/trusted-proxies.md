# 反向代理与客户端 IP（`trusted_proxies`）

Komari 记录的客户端 IP 来自三个来源，它们现在共用同一套可信代理解析：

- HTTP 访问日志、审计日志、会话列表中的登录 IP、终端请求方 IP、WebSocket 连接 IP；
- 插件上下文里的 `context.remote_ip`；
- 引导/恢复页面（`guide` 路由）。

## 默认行为：不信任任何转发头

`trusted_proxies` 默认为**空**。此时 `X-Forwarded-For` 与 `X-Real-IP` 一律被忽略，
客户端 IP 永远是 TCP 连接的源地址。

这是安全默认值：如果默认信任转发头，任何能直连服务的客户端都能自行决定日志与会话里记录的地址。

## 升级影响（重要）

如果 Komari 部署在反向代理、负载均衡或 CDN 之后，升级后**必须**显式配置代理地址，否则：

- 审计日志、会话列表、终端与插件上下文里记录的都会是代理地址，而不是真实客户端；
- 所有访问者表现为同一个来源，"按 IP 区分请求"的能力消失；
- 启动日志会打印 `Trusted proxies: none (forwarded client IP headers are ignored)`，
  可据此确认当前处于默认状态。

关于登录限流：Komari 自身没有基于 IP 的登录失败限流（登录失败只返回凭据错误），
所以升级不会让内置限流失效。如果在反向代理 / WAF 上做限流，那一层看到的是真实客户端地址，
不受本配置影响。若后续要基于 Komari 记录的 IP 做风控或统计，必须先配置本项。

## 配置方式

格式：逗号分隔的 IPv4 / IPv6 地址或 CIDR。只填写**实际部署中作为直接对端**的代理地址。

```text
# 单个地址
KOMARI_TRUSTED_PROXIES=127.0.0.1

# 多个地址 / 网段（IPv6 同样支持）
KOMARI_TRUSTED_PROXIES=127.0.0.1,::1,10.0.0.0/8
```

两种来源，设置项优先：

1. 环境变量 `KOMARI_TRUSTED_PROXIES`（容器部署推荐，无需改数据库）；
2. 设置项 `trusted_proxies`（可通过 `admin:editSettings` 或等价的配置写入方式设置）。

设置项非空时覆盖环境变量；两者都为空即为默认的"不信任任何转发头"。
**修改后需要重启 Komari**：可信代理在构建路由时应用。

非法条目（拼写错误、非法的掩码等）会在启动时记录一条错误日志，并回退到"不信任任何转发头"，
不会退化成"配置错了就信任所有来源"。

## 解析规则

1. 先判断连接的**对端地址**是否在可信列表中；不在列表中，转发头被完全忽略。
2. 对端可信时，读取 `X-Forwarded-For`，**从右向左**只看代理追加的那一端：
   逐个跳过可信代理，遇到第一个合法但不可信的地址就把它作为客户端地址并立即停止。
3. 转发链中出现无法解析的条目时，整条转发头作废（不会跳过该条目继续向左取值，
   因为左边的条目可以由调用方随意填写），转而尝试 `X-Real-IP`，最后回退到连接地址。
4. 多级代理时，把**每一跳**的可信地址都写进列表，顺序无关。

## 常见部署示例

### nginx 与 Komari 同机

```nginx
location / {
    proxy_pass http://127.0.0.1:25774;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

```text
KOMARI_TRUSTED_PROXIES=127.0.0.1
```

### nginx 在 Docker 网络中

```text
# 只填 nginx 容器在该网络中的固定 IP 更稳妥
KOMARI_TRUSTED_PROXIES=172.18.0.5
```

把整个网段（例如 `172.18.0.0/16`）列入意味着该网段内**任意**容器都能声称任意客户端 IP。
网络里只有反向代理时可以接受，否则请用固定 IP。

### Caddy 同机

```caddyfile
example.com {
    reverse_proxy 127.0.0.1:25774
}
```

```text
KOMARI_TRUSTED_PROXIES=127.0.0.1
```

Caddy 默认会向 `X-Forwarded-For` 追加客户端地址，填 Caddy 自己的地址即可。

### Traefik / 其它容器反向代理

填写 Traefik 容器的固定 IP（或它所在的专用子网）：

```text
KOMARI_TRUSTED_PROXIES=172.20.0.2
```

### Cloudflare 或其它 CDN

把 CDN 的**回源地址段**写入列表，并在官方列表变更时同步更新：

```text
KOMARI_TRUSTED_PROXIES=173.245.48.0/20,103.21.244.0/22,...
```

更稳妥的做法是在防火墙层限制源站只接受该 CDN 回源，再信任对应的地址段。
不要用 `0.0.0.0/0` 代替这一步。

### 多级代理

客户端 → CDN → 本机 nginx → Komari：

```text
KOMARI_TRUSTED_PROXIES=127.0.0.1,<CDN 回源段>
```

## 验证

1. 启动日志应打印实际生效的列表：
   `Trusted proxies: ...`，或在未配置时打印 `Trusted proxies: none (...)`。
2. 直连服务并伪造请求头，确认它没有被采纳：

   ```bash
   curl -s -H 'X-Forwarded-For: 1.2.3.4' http://<host>:25774/api/admin/logs
   ```

   审计日志中应记录真实的连接地址。
3. 经过反向代理访问管理页面并登录一次，确认会话列表里显示的是真实客户端地址。

## 不要这样做

- 不要填 `0.0.0.0/0`、`::/0` 或过大的公网段：这等于回到"任何客户端都能自选 IP"的状态。
- 不要信任可能被客户端直连的地址；只信任实际部署中的代理。
- 不要在 nginx 上只用 `proxy_set_header X-Forwarded-For $http_x_forwarded_for`（只透传、不追加）。
  Komari 依赖最右侧条目，只有追加才能表达真实来源。
