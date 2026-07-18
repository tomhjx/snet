FROM golang:1.26.5-alpine AS builder

WORKDIR /src
COPY go.mod ./
COPY . ./
RUN go build -o /out/snet ./cmd/snet

FROM alpine:3.21

RUN apk add --no-cache ca-certificates
COPY --from=builder /out/snet /usr/local/bin/snet
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/snet"]
