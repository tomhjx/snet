BINARY ?= snet
IMAGE ?= tomhjx/snet
ARGS ?= -config configs/passive.json
CMD ?= ./cmd/snet

.PHONY: build test example-probe example-probe-loop example-proxy-https example-passive run docker-build docker-run compose-up compose-proxy compose-probe compose-down compose-logs clean

build:
	go build -o bin/$(BINARY) $(CMD)

test:
	go test ./...

example-probe:
	./examples/probe_multi_targets.sh

example-probe-loop:
	./examples/probe_loop.sh

example-proxy-https:
	./examples/proxy_https.sh

example-passive:
	./examples/passive_linux.sh

run:
	go run $(CMD) $(ARGS)

docker-build:
	docker build -t $(IMAGE) .

docker-run:
	docker run --rm --network host --cap-add NET_RAW --cap-add NET_ADMIN -v "$(HOME)/.snet:/root/.snet" $(IMAGE) $(ARGS)

compose-up:
	docker compose up --build snet

compose-proxy:
	docker compose --profile proxy up --build snet-proxy

compose-probe:
	docker compose --profile probe run --rm probe

compose-down:
	docker compose down

compose-logs:
	docker compose logs -f

clean:
	rm -rf bin
