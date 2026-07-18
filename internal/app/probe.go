package app

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

func runProbe(cfg config, out sink) error {
	targets := selectedProbeTargets(cfg)
	if len(targets) == 0 {
		return errors.New("-probe-target or -probe-targets is required in probe mode")
	}
	ctx := context.Background()
	var cancel context.CancelFunc
	if cfg.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, cfg.timeout)
		defer cancel()
	}
	runnerCfg := cfg
	runnerCfg.count = 0
	runner := &proxyServer{cfg: runnerCfg, output: out}
	protocols := selectedProtocols(cfg.protocols)
	var rounds int64
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		for _, target := range targets {
			targetCfg := cfg
			targetCfg.probeTarget = target
			for _, protocol := range protocols {
				runner.writeEvent(runProbeOnce(targetCfg, protocol))
			}
		}
		rounds++
		if cfg.probeInterval <= 0 || (cfg.count > 0 && rounds >= cfg.count) {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(cfg.probeInterval):
		}
	}
}

func runProbeOnce(cfg config, protocol string) event {
	start := time.Now()
	var e event
	var err error
	switch protocol {
	case "IP":
		e, err = probeIP(cfg, start)
	case "Domain":
		e, err = probeDomain(cfg, start)
	case "TCP":
		e, err = probeTCP(cfg, start)
	case "UDP":
		e, err = probeUDP(cfg, start)
	case "Socket":
		e, err = probeSocket(cfg, start)
	case "WebSocket":
		e, err = probeWebSocket(cfg, start)
	case "AMQP":
		e, err = probeAMQP(cfg, start)
	case "MySQL":
		e, err = probeMySQL(cfg, start)
	case "HTTP":
		e, err = probeHTTP(cfg, "http", start)
	case "HTTPS":
		e, err = probeHTTP(cfg, "https", start)
	}
	if err != nil {
		e = baseProbeEvent(protocol, cfg.probeTarget, start)
		e.Error = err.Error()
	} else {
		e.Success = true
	}
	return e
}

func selectedProtocols(value string) []string {
	if strings.TrimSpace(value) == "" || strings.EqualFold(strings.TrimSpace(value), "all") {
		return []string{"IP", "Domain", "TCP", "UDP", "Socket", "WebSocket", "AMQP", "MySQL", "HTTP", "HTTPS"}
	}
	seen := make(map[string]bool)
	var protocols []string
	for part := range strings.SplitSeq(value, ",") {
		protocol := canonicalProtocol(part)
		if protocol == "" || seen[protocol] {
			continue
		}
		seen[protocol] = true
		protocols = append(protocols, protocol)
	}
	return protocols
}

func selectedProbeTargets(cfg config) []string {
	seen := make(map[string]bool)
	var targets []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		targets = append(targets, value)
	}
	for target := range strings.SplitSeq(cfg.probeTargets, ",") {
		add(target)
	}
	add(cfg.probeTarget)
	return targets
}

func baseProbeEvent(protocol string, target string, start time.Time) event {
	now := time.Now()
	return event{
		Timestamp: now.Format(time.RFC3339Nano),
		Protocol:  protocol,
		Stage:     strings.ToLower(protocol) + "_probe",
		FlowID:    normalizedFlowID("probe", target),
		Target:    target,
		StageMS:   now.Sub(start).Milliseconds(),
		TotalMS:   now.Sub(start).Milliseconds(),
	}
}

func probeIP(cfg config, start time.Time) (event, error) {
	host, _, _ := splitTarget(cfg.probeTarget, "")
	ips, err := net.LookupIP(host)
	e := baseProbeEvent("IP", cfg.probeTarget, start)
	e.Domain = host
	if err != nil {
		return e, err
	}
	for _, ip := range ips {
		e.Addresses = append(e.Addresses, ip.String())
	}
	return e, nil
}

func probeDomain(cfg config, start time.Time) (event, error) {
	host, _, _ := splitTarget(cfg.probeTarget, "")
	addresses, err := net.LookupHost(host)
	e := baseProbeEvent("Domain", cfg.probeTarget, start)
	e.Domain = host
	e.Addresses = addresses
	return e, err
}

func probeTCP(cfg config, start time.Time) (event, error) {
	address := targetWithDefaultPort(cfg.probeTarget, "80")
	e := baseProbeEvent("TCP", address, start)
	conn, err := net.DialTimeout("tcp", address, cfg.probeTimeout)
	if err != nil {
		return e, err
	}
	defer conn.Close()
	fillAddrFields(&e, conn.LocalAddr(), conn.RemoteAddr())
	return e, nil
}

func probeUDP(cfg config, start time.Time) (event, error) {
	address := targetWithDefaultPort(cfg.probeTarget, "53")
	e := baseProbeEvent("UDP", address, start)
	conn, err := net.DialTimeout("udp", address, cfg.probeTimeout)
	if err != nil {
		return e, err
	}
	defer conn.Close()
	fillAddrFields(&e, conn.LocalAddr(), conn.RemoteAddr())
	payload := []byte(cfg.probePayload)
	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			return e, err
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(cfg.probeTimeout))
	buf := make([]byte, cfg.bodyLimit)
	n, err := conn.Read(buf)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return e, nil
		}
		return e, err
	}
	fillPayload(&e, buf[:n], cfg.bodyLimit)
	return e, nil
}

func probeSocket(cfg config, start time.Time) (event, error) {
	address := targetWithDefaultPort(cfg.probeTarget, "9000")
	e := baseProbeEvent("Socket", address, start)
	conn, err := net.DialTimeout("tcp", address, cfg.probeTimeout)
	if err != nil {
		return e, err
	}
	defer conn.Close()
	fillAddrFields(&e, conn.LocalAddr(), conn.RemoteAddr())
	if cfg.probePayload != "" {
		if _, err := conn.Write([]byte(cfg.probePayload)); err != nil {
			return e, err
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(cfg.probeTimeout))
	buf := make([]byte, cfg.bodyLimit)
	n, err := conn.Read(buf)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return e, nil
		}
		return e, err
	}
	fillPayload(&e, buf[:n], cfg.bodyLimit)
	return e, nil
}

func probeWebSocket(cfg config, start time.Time) (event, error) {
	wsURL, err := parseWebSocketTarget(cfg.probeTarget)
	if err != nil {
		return event{}, err
	}
	e := baseProbeEvent("WebSocket", wsURL.String(), start)
	address := targetWithDefaultPort(wsURL.Host, map[bool]string{true: "443", false: "80"}[wsURL.Scheme == "wss"])
	conn, err := net.DialTimeout("tcp", address, cfg.probeTimeout)
	if err != nil {
		return e, err
	}
	defer conn.Close()
	if wsURL.Scheme == "wss" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: hostnameOnly(address), MinVersion: tls.VersionTLS12})
		if err := tlsConn.Handshake(); err != nil {
			return e, err
		}
		conn = tlsConn
	}
	fillAddrFields(&e, conn.LocalAddr(), conn.RemoteAddr())
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return e, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	path := wsURL.RequestURI()
	if path == "" {
		path = "/"
	}
	request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", path, wsURL.Host, key)
	if _, err := io.WriteString(conn, request); err != nil {
		return e, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(cfg.probeTimeout))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return e, err
	}
	defer resp.Body.Close()
	e.Status = resp.StatusCode
	e.ResponseHeaders = cloneHeader(resp.Header)
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return e, fmt.Errorf("websocket upgrade status %d", resp.StatusCode)
	}
	return e, nil
}

func probeAMQP(cfg config, start time.Time) (event, error) {
	address := targetWithDefaultPort(cfg.probeTarget, "5672")
	e := baseProbeEvent("AMQP", address, start)
	conn, err := net.DialTimeout("tcp", address, cfg.probeTimeout)
	if err != nil {
		return e, err
	}
	defer conn.Close()
	fillAddrFields(&e, conn.LocalAddr(), conn.RemoteAddr())
	if _, err := conn.Write([]byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1}); err != nil {
		return e, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(cfg.probeTimeout))
	buf := make([]byte, cfg.bodyLimit)
	n, err := conn.Read(buf)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return e, nil
		}
		return e, err
	}
	fillPayload(&e, buf[:n], cfg.bodyLimit)
	return e, nil
}

func probeMySQL(cfg config, start time.Time) (event, error) {
	address := targetWithDefaultPort(cfg.probeTarget, "3306")
	e := baseProbeEvent("MySQL", address, start)
	conn, err := net.DialTimeout("tcp", address, cfg.probeTimeout)
	if err != nil {
		return e, err
	}
	defer conn.Close()
	fillAddrFields(&e, conn.LocalAddr(), conn.RemoteAddr())
	_ = conn.SetReadDeadline(time.Now().Add(cfg.probeTimeout))
	buf := make([]byte, cfg.bodyLimit)
	n, err := conn.Read(buf)
	if err != nil {
		return e, err
	}
	fillPayload(&e, buf[:n], cfg.bodyLimit)
	if query := parseMySQLQuery(buf[:n]); query != "" {
		e.Query = query
		e.Transaction = classifyMySQLTransaction(query)
	}
	if version := parseMySQLServerVersion(buf[:n]); version != "" {
		e.ResponseHeaders = map[string][]string{"server_version": {version}}
	}
	return e, nil
}

func probeHTTP(cfg config, scheme string, start time.Time) (event, error) {
	target := cfg.probeTarget
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = scheme + "://" + target
	}
	e := baseProbeEvent(strings.ToUpper(scheme), target, start)
	method := http.MethodGet
	var body io.Reader
	if cfg.probePayload != "" {
		method = http.MethodPost
		body = strings.NewReader(cfg.probePayload)
	}
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		return e, err
	}
	client := &http.Client{Timeout: cfg.probeTimeout, Transport: &http.Transport{DisableCompression: true}}
	requestBody, err := captureAndReplaceBody(req, cfg.bodyLimit)
	if err != nil {
		return e, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return e, err
	}
	defer resp.Body.Close()
	responseBody, err := captureResponseBody(resp, cfg.bodyLimit)
	if err != nil {
		return e, err
	}
	e = (&proxyServer{cfg: cfg}).makeEvent(strings.ToUpper(scheme), "probe", req.URL.Host, req, resp, requestBody, responseBody, start)
	return e, nil
}
