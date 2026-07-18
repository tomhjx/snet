# Development

本文档记录 `snet` 的开发环境、项目结构和本地验证命令。用户使用说明见 [README.md](README.md)。

## Go 版本

项目基于 Go 1.26 开发，`go.mod` 使用：

```text
go 1.26
toolchain go1.26.5
```

Docker 构建镜像使用 `golang:1.26.5-alpine`。

## 项目结构

```text
.
├── cmd/
│   └── snet/
│       └── main.go      # CLI 薄入口，只调用 internal/app
├── internal/
│   └── app/
│       ├── app.go       # 应用生命周期：参数校验、模式分发、监听启动
│       ├── config.go    # CLI 参数和默认配置
│       ├── output.go    # stdout、syslog、Unix socket 输出
│       ├── event.go     # 事件模型、body/payload 捕获与编码
│       ├── proxy.go     # HTTPS 代理嗅探和 CONNECT MITM 转发
│       ├── ca.go        # 本地 CA、证书加载、按域名动态签发证书
│       ├── probe.go     # IP/DNS/TCP/UDP/WebSocket/AMQP/MySQL/HTTP 主动探测
│       ├── sniff.go     # TCP/UDP payload 被动识别工具
│       ├── protocol.go  # 协议识别、DNS/MySQL 解析、地址工具
│       └── app_test.go  # 核心行为测试
├── configs/             # 示例配置文件
├── examples/            # 可直接运行的使用示例
├── compose.yaml
├── Dockerfile
├── Makefile
├── go.mod
└── README.md
```

## 设计约束

- `cmd/snet` 保持薄入口，不放业务逻辑。
- `internal/app` 按职责拆分文件，接近主流 Go CLI 项目布局。
- 业务实现不暴露为 public package，避免外部项目误导入未稳定 API。
- 测试跟随核心模块放在 `internal/app`。
- 默认 sniff 路径必须非干扰：不代理、不转发、不主动连接监听目标。
- 明文协议优先通过 passive 嗅探解析；只有 HTTPS 明文调试允许显式 `proxy` / MITM。

## 本地验证

```bash
gofmt -w internal/app/*.go cmd/snet/main.go
go test ./...
go build ./cmd/snet
```

Linux passive parser 交叉编译验证：

```bash
GOOS=linux GOARCH=amd64 go test -c ./internal/app
```

Docker Compose 配置验证：

```bash
docker compose config
docker compose --profile proxy config
docker compose --profile probe config
```

Docker 镜像构建验证：

```bash
docker build -t snet:dev .
```
