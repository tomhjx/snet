# snet

`snet` 是一个基于 Go 的轻量网络嗅探与探测工具，用于收集网络连接、协议识别、请求内容、响应内容和阶段耗时。

当前支持两类工作模式：

- `sniff`：默认被动监听网卡流量，不代理、不转发、不改变目标服务流量路径。
- `probe`：主动访问目标服务，输出连接结果、协议握手、请求/响应内容和耗时。

> 工具目标是不干扰监听目标。默认 `-capture-mode passive` 使用 Linux `AF_PACKET` 被动读取镜像/本机网卡流量。HTTP 明文可被动识别请求/响应片段；HTTPS 在非干扰模式下只能看到 IP、端口、TLS 握手/SNI 等明文元数据，不能获取加密后的请求/响应 body。需要 HTTPS 明文时，必须显式切到 `-capture-mode proxy`，这是调试/MITM 模式，不属于默认非干扰路径。

## 功能特性

- 支持协议：IP、Domain/DNS、TCP、UDP、WebSocket、Socket、AMQP、MySQL、HTTP、HTTPS。
- 被动嗅探：不代理、不转发、不主动连接目标服务。
- HTTP 被动识别：从 TCP payload 中识别 HTTP request/response 片段。
- HTTPS 非干扰识别：默认不解密，只输出连接/TLS 明文元数据；MITM 仅作为显式调试模式。
- TCP/UDP 被动识别：默认从网卡被动解析 TCP segment 和 UDP datagram，识别 DNS、HTTP、WebSocket Upgrade、AMQP header、MySQL handshake/query（含具体 SQL 和事务语义）和普通 Socket payload。
- 主动探测模式：对指定目标执行 IP 解析、DNS 解析、TCP/UDP 连接、Socket 收发、WebSocket Upgrade、AMQP 握手、MySQL 握手、HTTP/HTTPS 请求。
- 输出格式：Text、JSON。
- 输出目标：STDOUT、syslog、Unix datagram socket。
- 输出模式：`content`、`full`、`timing`。
- body/payload 输出上限控制；文本原样输出，二进制 base64 输出。

## 支持矩阵

| 协议 | Sniff 支持 | Probe 支持 | 说明 |
| --- | --- | --- | --- |
| IP | 是 | 是 | Sniff 被动输出连接/datagram 元信息；Probe 解析目标 IP。 |
| Domain / DNS | 是 | 是 | Sniff 被动解析 UDP DNS question；Probe 使用系统 resolver。 |
| TCP | 是 | 是 | Sniff 被动记录 TCP 连接和 payload；Probe 建立 TCP 连接。 |
| UDP | 是 | 是 | Sniff 被动记录 UDP datagram；Probe 发送 payload 并尝试读取响应。 |
| WebSocket | 是 | 是 | Sniff 被动识别 HTTP Upgrade；Probe 发起 WebSocket Upgrade。 |
| Socket | 是 | 是 | Sniff 被动记录普通 TCP payload；Probe 发送/接收 TCP payload。 |
| AMQP | 是 | 是 | Sniff 被动识别 `AMQP` 协议头或 5672 端口；Probe 发送 AMQP protocol header。 |
| MySQL | 是 | 是 | Sniff 被动识别 3306/33060 或 MySQL packet，解析明文 `COM_QUERY` SQL 和事务语句；Probe 读取握手包和 server version。 |
| HTTP | 是 | 是 | Sniff 被动解析明文 HTTP payload；Probe 发起 HTTP 请求。 |
| HTTPS | 元数据 | 是 | Sniff 默认不解密；MITM 明文获取仅在显式 `proxy` 调试模式。 |

## 安装

### 源码构建

```bash
go build -o bin/snet ./cmd/snet
```

### Makefile

```bash
make build
make test
make run ARGS="-mode sniff -capture-mode passive -iface eth0 -f json -m full"
make run ARGS="-config configs/passive.json -iface eth0"
```

### Docker

```bash
make docker-build
make docker-run ARGS="-mode sniff -capture-mode passive -iface eth0 -f json -m full"
```

直接运行 Docker：

```bash
docker build -t tomhjx/snet .
docker run --rm --network host --cap-add NET_RAW --cap-add NET_ADMIN tomhjx/snet -mode sniff -capture-mode passive -iface eth0 -f json -m full
```

### Docker Compose

默认启动非干扰被动嗅探：

```bash
docker compose up --build snet
# 或
make compose-up
```

显式启动 HTTPS MITM 调试模式：

```bash
docker compose --profile proxy up --build snet-proxy
# 或
make compose-proxy
```

执行一次主动探测：

```bash
TARGETS=example.com:80,example.org:80 PROTOCOLS=ip,domain,tcp,http docker compose --profile probe run --rm probe
# 或
TARGETS=example.com:80,example.org:80 PROTOCOLS=ip,domain,tcp,http make compose-probe
```

常用环境变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `IMAGE` | `tomhjx/snet:local` | Compose 构建/运行镜像名。 |
| `CONFIG` | `/etc/snet/passive.json` | 容器内配置文件路径；默认挂载本仓库 `configs/`。 |
| `PROXY_CONFIG` | `/etc/snet/proxy.yaml` | `proxy` profile 使用的配置文件路径。 |
| `PROBE_CONFIG` | `/etc/snet/probe.yaml` | `probe` profile 使用的配置文件路径。 |
| `FORMAT` | `json` | 输出格式。 |
| `SNIFF_MODE` | `full` | 嗅探输出模式。 |
| `IFACE` | 空 | 被动嗅探网卡；为空监听所有接口。 |
| `HTTPS_PROXY_PORT` | `8080` | HTTPS 代理暴露端口。 |
| `TARGETS` | `example.com:80,example.org:80` | 逗号分隔 probe 目标。 |
| `PROTOCOLS` | `ip,domain,tcp,http` | probe 协议列表。 |
| `PROBE_INTERVAL` | `0s` | probe 轮询间隔；`0s` 表示只执行一次。 |
| `PROBE_COUNT` | `1` | probe 轮数；配合 `PROBE_INTERVAL` 使用。 |
| `PROBE_TIMEOUT` | `5s` | probe 超时。 |
| `PROBE_PAYLOAD` | `ping` | probe payload。 |

Compose 使用名为 `snet-ca` 的 volume 保存 `~/.snet`，方便复用 HTTPS MITM CA。
`compose.yaml` 中宿主机路径尽量使用相对路径，例如 `build.context: .` 和 `source: ./configs`。

## 配置文件

除命令行参数外，`snet` 也支持通过 `-config` 读取配置文件工作。支持 JSON 和简单平铺 YAML；命令行显式参数优先级更高。

加载顺序：默认值 < 配置文件 < 命令行显式参数。

```bash
snet -config configs/passive.json -iface eth0
snet -config configs/proxy.yaml -f text
snet -config configs/probe.yaml -targets example.com:80,example.org:80
```

JSON 示例：

```json
{
  "mode": "sniff",
  "capture_mode": "passive",
  "iface": "eth0",
  "format": "json",
  "fields": "timestamp,protocol,source_ip,destination_ip,query,transaction",
  "sniff_mode": "full",
  "protocols": "all",
  "body_limit": 65536
}
```

YAML 示例：

```yaml
mode: sniff
capture_mode: proxy
listen: :8080
format: json
sniff_mode: full
protocols: https
```

## 快速开始

### 默认非干扰被动嗅探

Linux 上启动被动嗅探，不改变目标流量路径：

```bash
sudo snet -mode sniff -capture-mode passive -iface eth0 -f json -m full
```

Docker 启动需要 host network 和 raw socket 权限：

```bash
docker run --rm --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  tomhjx/snet -mode sniff -capture-mode passive -iface eth0 -f json -m full
```

HTTP 明文请求/响应会从被动 TCP payload 中识别；HTTPS 默认不解密，只输出连接/TLS 明文元数据。

只看 TCP/UDP：

```bash
sudo snet -mode sniff -capture-mode passive -iface eth0 -P tcp,udp -f json -m full
```

被动 TCP/UDP 嗅探不会监听端口，也不会改变目标连接；它读取网卡上的 IPv4 TCP/UDP 包并解析 payload。

### 显式 proxy 调试模式

只有需要调试 HTTPS 明文时，才启用代理/MITM：

```bash
docker compose --profile proxy up --build snet-proxy

curl -x http://127.0.0.1:8080 \
  --cacert ~/.snet/snet-ca.pem \
  -H 'Content-Type: application/json' \
  -d '{"hello":"https"}' \
  https://httpbin.org/post
```

`proxy` 模式会改变客户端流量路径，不是默认非干扰模式。

### 明文协议被动识别示例

普通 Socket payload：

```bash
printf 'hello socket' | nc 127.0.0.1 9000
```

WebSocket Upgrade 识别：

```bash
curl -i \
  -H 'Connection: Upgrade' \
  -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==' \
  -H 'Sec-WebSocket-Version: 13' \
  http://127.0.0.1:9000/ws
```

AMQP 协议头识别：

```bash
printf 'AMQP\x00\x00\x09\x01' | nc 127.0.0.1 9000
```

MySQL 最小查询包识别：

```bash
printf '\x09\x00\x00\x00\x03select 1' | nc 127.0.0.1 9000
```

被动 MySQL 明文解析会把登录包用户名输出到 `account` 字段，把 `COM_QUERY` 输出到 `query` 字段，并对事务语句填充 `transaction` 字段。账号会按 TCP flow 关联到后续 SQL 事件。

MySQL query 事件未显式指定 `-fields` 时，默认只展示：

```text
destination_ip,destination_port,account,query
```

事务识别：

```text
BEGIN                  -> transaction=begin
START TRANSACTION      -> transaction=begin
COMMIT                 -> transaction=commit
ROLLBACK               -> transaction=rollback
SAVEPOINT sp1          -> transaction=savepoint
RELEASE SAVEPOINT sp1  -> transaction=release_savepoint
SET autocommit=0       -> transaction=set_autocommit_off
SET autocommit=1       -> transaction=set_autocommit_on
```

### 主动探测

探测所有支持协议：

```bash
snet -mode probe -target example.com:80 -f json
```

指定多个目标：

```bash
snet -mode probe -targets example.com:80,example.org:80 -P tcp,http -f json
```

按频率循环探测：

```bash
snet -mode probe -targets example.com:80,example.org:80 -P tcp,http -probe-interval 10s -count 6 -f json
```

说明：`-probe-interval` 为 `0` 时只执行一轮；大于 `0` 时按间隔循环。Probe 模式下 `-count` 表示轮数，`0` 表示持续运行，直到 `-timeout` 或进程退出。

只探测指定协议：

```bash
snet -mode probe -target example.com -P ip,domain -f json
snet -mode probe -target example.com:80 -P tcp,http -f json
snet -mode probe -target ws://example.com/ws -P websocket -f json
snet -mode probe -target 127.0.0.1:5672 -P amqp -f json
snet -mode probe -target 127.0.0.1:3306 -P mysql -f json
```

UDP/Socket 探测自定义 payload：

```bash
snet -mode probe -target 127.0.0.1:9000 -P socket -probe-payload 'hello'
snet -mode probe -target 8.8.8.8:53 -P udp -probe-payload 'ping'
```

## HTTPS CA 证书

首次启动 HTTPS 嗅探时，`snet` 会自动生成：

- `~/.snet/snet-ca.pem`
- `~/.snet/snet-ca-key.pem`

仅当前 `curl` 命令信任 CA：

```bash
curl --cacert ~/.snet/snet-ca.pem -x http://127.0.0.1:8080 https://example.com
```

macOS 系统级信任：

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.snet/snet-ca.pem
```

Debian / Ubuntu 系统级信任：

```bash
sudo cp ~/.snet/snet-ca.pem /usr/local/share/ca-certificates/snet-ca.crt
sudo update-ca-certificates
```

## 命令行参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-config` | 空 | 配置文件路径，支持 JSON 或简单平铺 YAML；CLI 显式参数会覆盖配置文件。 |
| `-mode` | `sniff` | 运行模式：`sniff` 或 `probe`。 |
| `-capture-mode` | `passive` | 嗅探捕获模式：`passive` 非干扰被动抓包，`proxy` 显式代理/调试模式。 |
| `-listen` | `:8080` | `proxy` 模式下 HTTPS 代理监听地址。 |
| `-iface`, `-i` | 空 | `passive` 模式下监听网卡；为空监听所有接口。 |
| `-format`, `-f` | `text` | 输出格式：`text`、`json`。 |
| `-fields` | 空 | 逗号分隔的输出字段白名单；为空输出除 `payload*` 外的默认字段；`all` 输出全部非空字段。 |
| `-output`, `-o` | `stdout` | 输出目标：`stdout`、`syslog`、`unix`。 |
| `-output-path`, `-p` | `/tmp/cnet.sock` | Unix datagram socket 路径。 |
| `-protocols`, `-P` | `all` | 协议过滤：`ip,domain,tcp,udp,websocket,socket,amqp,mysql,http,https`。 |
| `-sniff-mode`, `-m` | `content` | 输出模式：`content`、`full`、`timing`。 |
| `-probe-target`, `-target` | 空 | Probe 模式目标，支持 host、host:port、URL。 |
| `-probe-targets`, `-targets` | 空 | 逗号分隔的多个 Probe 目标；会与 `-probe-target` 合并去重。 |
| `-probe-payload` | `ping` | UDP、Socket、HTTP、HTTPS 等探测 payload。 |
| `-probe-timeout` | `5s` | 单个协议探测超时。 |
| `-probe-interval` | `0s` | Probe 轮询间隔；`0s` 表示只执行一次。 |
| `-count`, `-c` | `0` | Sniff 模式为事件数限制；Probe 模式为轮数，`0` 表示持续运行。 |
| `-timeout`, `-t` | `0` | 运行时长；`0` 表示持续运行。 |
| `-ca-cert` | `~/.snet/snet-ca.pem` | HTTPS MITM 根 CA 证书路径。 |
| `-ca-key` | `~/.snet/snet-ca-key.pem` | HTTPS MITM 根 CA 私钥路径。 |
| `-body-limit` | `65536` | body/payload 最大输出字节数；代理转发仍保留完整 body。 |

## 输出字段

JSON 和 Text 使用同一套字段名。Text 输出格式为 `field=value`；JSON 输出为同名 key。

可用 `-fields` 指定展示字段：

```bash
snet -config configs/passive.json -fields timestamp,protocol,source_ip,destination_ip,query,transaction
```

默认输出不会展示 `payload`、`payload_encoding`、`payload_truncated`。`sniff` 事件默认也不展示 `success`；`probe` 事件默认保留 `success`。HTTP/HTTPS 事件默认展示请求/响应信息字段，如 headers、body、status。其他字段仍按默认规则输出。如需 payload，显式指定字段：

```bash
snet -config configs/passive.json -fields timestamp,protocol,source_ip,destination_ip,payload
snet -config configs/passive.json -fields all
```

字段命名原则：同一语义跨协议使用同一个字段名。例如 HTTP query string 和 MySQL SQL 都使用 `query`；源/目标地址统一使用 `source_*` / `destination_*`。避免同时输出 `source` 与 `source_ip/source_port` 这类重复语义字段。

| 字段 | 说明 | 适用协议/场景 |
| --- | --- | --- |
| `timestamp` | 事件时间。 | 全部 |
| `protocol` | 识别出的协议：IP、Domain、TCP、UDP、WebSocket、Socket、AMQP、MySQL、HTTP、HTTPS。 | 全部 |
| `stage` | 事件阶段，如 `dns_packet`、`tcp_probe`、`mysql_query`、`https_response`。 | 全部 |
| `flow_id` | 归一化 flow ID。 | 全部 |
| `target` | 用户指定或代理访问的目标。 | Probe/HTTPS proxy |
| `source_ip` | 源 IP。 | IP/TCP/UDP |
| `destination_ip` | 目标 IP。 | IP/TCP/UDP |
| `source_port` | 源端口。 | TCP/UDP |
| `destination_port` | 目标端口。 | TCP/UDP |
| `length` | 当前 payload 长度。 | IP/TCP/UDP/Socket/MySQL |
| `domain` | 域名。 | DNS/Domain |
| `addresses` | 域名解析结果。 | Probe Domain/IP |
| `method` | 请求方法，例如 HTTP method。 | HTTP/HTTPS/WebSocket |
| `scheme` | URL scheme。 | HTTP/HTTPS |
| `host` | 主机名或 Host header。 | HTTP/HTTPS/WebSocket |
| `account` | 账号/用户名。 | MySQL |
| `path` | 请求路径。 | HTTP/HTTPS/WebSocket |
| `query` | 查询内容。HTTP 中为 query string；MySQL 中为明文 `COM_QUERY` SQL。 | HTTP/MySQL |
| `transaction` | 事务语义，如 `begin`、`commit`、`rollback`、`set_autocommit_off`。 | MySQL |
| `status` | 响应状态码。 | HTTP/HTTPS/WebSocket |
| `request_headers` | 请求头。 | HTTP/HTTPS |
| `response_headers` | 响应头或协议解析出的响应元数据，例如 MySQL server_version。 | HTTP/HTTPS/MySQL |
| `request_body` | 请求 body。 | HTTPS proxy/debug、HTTP probe |
| `response_body` | 响应 body。 | HTTPS proxy/debug、HTTP probe |
| `request_encoding` | `request_body` 编码：`text` 或 `base64`。 | HTTP/HTTPS |
| `response_encoding` | `response_body` 编码：`text` 或 `base64`。 | HTTP/HTTPS |
| `request_truncated` | 请求 body 是否被截断。 | HTTP/HTTPS |
| `response_truncated` | 响应 body 是否被截断。 | HTTP/HTTPS |
| `payload` | 协议 payload。 | TCP/UDP/Socket/AMQP/MySQL |
| `payload_encoding` | `payload` 编码：`text` 或 `base64`。 | TCP/UDP/Socket/AMQP/MySQL |
| `payload_truncated` | payload 是否被截断。 | TCP/UDP/Socket/AMQP/MySQL |
| `success` | 探测或解析是否成功。 | Probe/Packet |
| `stage_ms` | 当前阶段耗时毫秒数。 | `full`/`timing` |
| `total_ms` | flow 总耗时毫秒数。 | `full`/`timing` |
| `error` | 错误信息。 | 错误事件 |

## 输出模式

- `content`：输出识别内容，不输出耗时。
- `full`：输出识别内容和阶段耗时。
- `timing`：只输出阶段耗时，不输出 host、path、headers、body、payload 等内容字段。

## 输出到 Unix Socket

启动接收端：

```bash
socat -u UNIX-RECVFROM:/tmp/cnet.sock,fork -
```

启动 `snet`：

```bash
snet -o unix -p /tmp/cnet.sock -f json
```

## 安全说明

- `snet-ca-key.pem` 是根 CA 私钥，必须妥善保管，不能提交到仓库或共享给他人。
- HTTPS 解密只能用于你拥有授权的测试、调试和排障场景。
- 系统级信任 CA 后，任何持有该 CA 私钥的程序都能签发被系统信任的证书；测试完成后建议移除信任。
- `sniff` 监听端口默认无认证；不要暴露到不可信网络。

## 限制

- `passive` 模式依赖 Linux `AF_PACKET` raw socket，需要 root 或 `NET_RAW`/`NET_ADMIN` 权限。
- 非 Linux 系统可构建和运行 probe，但被动嗅探会返回“不支持”错误。
- HTTPS 明文内容无法在非干扰模式下获取；只能看到 TLS 握手等明文元数据。获取 HTTPS body 必须启用显式 `proxy` MITM 调试模式。
- `proxy` 模式会改变客户端 HTTPS 流量路径，不属于默认非干扰模式；明文 HTTP/TCP/UDP 不提供主动嗅探入口，使用 `passive` 被动嗅探。
- 被动 TCP payload 解析不做完整 TCP stream 重组；跨包 HTTP body 可能只输出片段。

## 开发文档

开发环境、项目结构、设计约束和本地验证命令见 [DEVELOPMENT.md](DEVELOPMENT.md)。

### 示例脚本

可直接运行的使用示例位于 `examples/`：

| 脚本 | 说明 |
| --- | --- |
| `examples/probe_multi_targets.sh` | 一次性探测多个目标。 |
| `examples/probe_loop.sh` | 按固定频率循环探测多个目标。 |
| `examples/proxy_https.sh` | 启动 HTTPS proxy/MITM 并发起一次 HTTPS 请求。 |
| `examples/passive_linux.sh` | Linux 上执行非干扰被动嗅探。 |

运行示例：

```bash
./examples/probe_multi_targets.sh
./examples/probe_loop.sh
./examples/proxy_https.sh
sudo IFACE=eth0 ./examples/passive_linux.sh
```

也可通过 Makefile：

```bash
make example-probe
make example-probe-loop
make example-proxy-https
make example-passive
```

常用覆盖参数：

```bash
TARGETS=example.com:80,example.org:80 PROTOCOLS=tcp,http ./examples/probe_multi_targets.sh
TARGETS=example.com:80 INTERVAL=5s COUNT=12 ./examples/probe_loop.sh
PORT=18080 TARGET_URL=https://example.com/ ./examples/proxy_https.sh
IFACE=eth0 PROTOCOLS=tcp,udp,mysql ./examples/passive_linux.sh
```

## License

未声明。发布前请补充许可证文件。
