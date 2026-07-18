package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"
)

func Main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		log.Fatal(err)
	}
}

func run(cfg config) error {
	if cfg.mode != "sniff" && cfg.mode != "probe" {
		return fmt.Errorf("unsupported mode %q", cfg.mode)
	}
	if cfg.format != "text" && cfg.format != "json" {
		return fmt.Errorf("unsupported format %q", cfg.format)
	}
	if cfg.sniffMode != "content" && cfg.sniffMode != "full" && cfg.sniffMode != "timing" {
		return fmt.Errorf("unsupported sniff mode %q", cfg.sniffMode)
	}
	if cfg.captureMode != "passive" && cfg.captureMode != "proxy" {
		return fmt.Errorf("unsupported capture mode %q", cfg.captureMode)
	}
	out, err := openSink(cfg)
	if err != nil {
		return err
	}
	defer out.Close()
	if cfg.mode == "probe" {
		return runProbe(cfg, out)
	}
	if cfg.captureMode == "passive" {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if cfg.timeout > 0 {
			timer := time.AfterFunc(cfg.timeout, cancel)
			defer timer.Stop()
		}
		return runPassiveSniffer(ctx, cfg, out)
	}

	caCert, caKey, err := loadOrCreateCA(cfg.caCertPath, cfg.caKeyPath)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		return err
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := &proxyServer{
		cfg:    cfg,
		output: out,
		transport: &http.Transport{
			Proxy:               nil,
			DisableCompression:  true,
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		caCert: caCert,
		caKey:  caKey,
		certs:  make(map[string]*tls.Certificate),
		stop: func() {
			cancel()
			_ = listener.Close()
		},
	}
	if cfg.timeout > 0 {
		timer := time.AfterFunc(cfg.timeout, func() {
			cancel()
			_ = listener.Close()
		})
		defer timer.Stop()
	}
	log.Printf("snet HTTPS proxy listening on %s; HTTPS CA certificate: %s", cfg.listen, cfg.caCertPath)
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go server.handleConn(ctx, conn)
	}
}
