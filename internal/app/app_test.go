package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type memorySink struct {
	mu     sync.Mutex
	events []event
}

func (s *memorySink) Write(e event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return nil
}

func (s *memorySink) Close() error { return nil }

func (s *memorySink) last() event {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) == 0 {
		return event{}
	}
	return s.events[len(s.events)-1]
}

func TestEncodeBodyText(t *testing.T) {
	body := encodeBody([]byte("hello"), false)
	if body.Value != "hello" || body.Encoding != "text" || body.Truncated {
		t.Fatalf("unexpected body: %+v", body)
	}
}

func TestEncodeBodyBase64(t *testing.T) {
	body := encodeBody([]byte{0, 1, 2}, true)
	if body.Value != "AAEC" || body.Encoding != "base64" || !body.Truncated {
		t.Fatalf("unexpected body: %+v", body)
	}
}

func TestCaptureAndReplaceBody(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "http://example.com", io.NopCloser(bytes.NewBufferString("abcdef")))
	if err != nil {
		t.Fatal(err)
	}
	body, err := captureAndReplaceBody(req, 3)
	if err != nil {
		t.Fatal(err)
	}
	if body.Value != "abc" || !body.Truncated {
		t.Fatalf("unexpected capture: %+v", body)
	}
	forwarded, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(forwarded) != "abcdef" {
		t.Fatalf("unexpected forwarded body %q", string(forwarded))
	}
}

func TestOutputFieldsFilterTextAndJSON(t *testing.T) {
	e := event{
		Timestamp:       "2026-01-01T00:00:00Z",
		Protocol:        "MySQL",
		FlowID:          "flow-1",
		SourceIP:        "10.0.0.1",
		DestinationIP:   "10.0.0.2",
		SourcePort:      12345,
		DestinationPort: 3306,
		Query:           "BEGIN",
		Transaction:     "begin",
	}
	fields := outputFieldsFromConfig("protocol,source_ip,destination_ip,query,transaction")
	line := textLine(e, fields)
	if line != `protocol=MySQL source_ip=10.0.0.1 destination_ip=10.0.0.2 query="BEGIN" transaction=begin` {
		t.Fatalf("unexpected text line: %s", line)
	}
	jsonLine, err := renderLine("json", e, fields)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(jsonLine), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 5 || decoded["protocol"] != "MySQL" || decoded["source_ip"] != "10.0.0.1" || decoded["transaction"] != "begin" {
		t.Fatalf("unexpected filtered json: %s", jsonLine)
	}
	if _, ok := decoded["flow_id"]; ok {
		t.Fatalf("field filter leaked flow_id: %s", jsonLine)
	}
}

func TestMySQLQueryDefaultOutputFields(t *testing.T) {
	e := event{Protocol: "MySQL", DestinationIP: "10.0.0.2", DestinationPort: 3306, Account: "root", Query: "select 1", FlowID: "hidden"}
	line := textLine(e, nil)
	if line != `destination_ip=10.0.0.2 destination_port=3306 account=root query="select 1"` {
		t.Fatalf("unexpected MySQL default text line: %s", line)
	}
	jsonLine, err := renderLine("json", e, nil)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(jsonLine), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 4 || decoded["destination_ip"] != "10.0.0.2" || decoded["account"] != "root" || decoded["query"] != "select 1" {
		t.Fatalf("unexpected MySQL default json: %s", jsonLine)
	}
	if _, ok := decoded["flow_id"]; ok {
		t.Fatalf("MySQL default json leaked flow_id: %s", jsonLine)
	}
}

func TestDefaultOutputOmitsPayloadButKeepsOtherFields(t *testing.T) {
	e := event{
		Protocol:        "HTTP",
		Stage:           "http_packet",
		FlowID:          "flow-1",
		SourceIP:        "10.0.0.1",
		DestinationIP:   "10.0.0.2",
		RequestBody:     "secret request",
		ResponseBody:    "secret response",
		Payload:         "raw payload",
		PayloadEncoding: "text",
		Success:         true,
	}
	line := textLine(e, nil)
	if !strings.Contains(line, `request_body="secret request"`) || !strings.Contains(line, `response_body="secret response"`) {
		t.Fatalf("default text output omitted non-payload fields: %s", line)
	}
	if strings.Contains(line, "payload") {
		t.Fatalf("default text output leaked payload fields: %s", line)
	}
	if strings.Contains(line, "success") {
		t.Fatalf("sniff default text output leaked success: %s", line)
	}
	jsonLine, err := renderLine("json", e, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(jsonLine, "request_body") || !strings.Contains(jsonLine, "response_body") {
		t.Fatalf("default json output omitted non-payload fields: %s", jsonLine)
	}
	if strings.Contains(jsonLine, "payload") {
		t.Fatalf("default json output leaked payload fields: %s", jsonLine)
	}
	if strings.Contains(jsonLine, "success") {
		t.Fatalf("sniff default json output leaked success: %s", jsonLine)
	}
}

func TestProbeDefaultOutputKeepsSuccess(t *testing.T) {
	e := event{Protocol: "TCP", Stage: "tcp_probe", FlowID: "flow-1", Target: "example.com:80", Success: true}
	line := textLine(e, nil)
	if !strings.Contains(line, "success=true") {
		t.Fatalf("probe default text output omitted success: %s", line)
	}
	jsonLine, err := renderLine("json", e, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(jsonLine, "success") {
		t.Fatalf("probe default json output omitted success: %s", jsonLine)
	}
}

func TestFieldsAllIncludesRawContent(t *testing.T) {
	e := event{Protocol: "HTTP", FlowID: "flow-1", RequestBody: "secret request", Payload: "raw payload", PayloadEncoding: "text"}
	line := textLine(e, outputFieldsFromConfig("all"))
	if !strings.Contains(line, `request_body="secret request"`) || !strings.Contains(line, `payload="raw payload"`) {
		t.Fatalf("fields=all did not include raw content: %s", line)
	}
	jsonLine, err := renderLine("json", e, outputFieldsFromConfig("all"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(jsonLine, "request_body") || !strings.Contains(jsonLine, "payload") {
		t.Fatalf("fields=all json did not include raw content: %s", jsonLine)
	}
}

func TestParseArgsLoadsFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snet.yaml")
	content := "fields: protocol,query,transaction\nformat: json\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := parseArgs([]string{"-config", path, "-fields", "protocol,source_ip"})
	if cfg.format != "json" || cfg.fields != "protocol,source_ip" {
		t.Fatalf("fields config/override failed: %+v", cfg)
	}
}

func TestParseArgsLoadsConfigAndCLIOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snet.json")
	content := `{
		"mode": "probe",
		"capture_mode": "proxy",
		"format": "json",
		"protocols": "http",
		"probe_target": "example.com:80",
		"probe_targets": "example.org:80,example.net:80",
		"probe_timeout": "2s",
		"probe_interval": "4s",
		"body_limit": 1234
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := parseArgs([]string{"-config", path, "-f", "text", "-P", "tcp,http", "-probe-timeout", "3s"})
	if cfg.mode != "probe" || cfg.captureMode != "proxy" || cfg.probeTarget != "example.com:80" || cfg.probeTargets != "example.org:80,example.net:80" {
		t.Fatalf("config not loaded: %+v", cfg)
	}
	if cfg.format != "text" || cfg.protocols != "tcp,http" || cfg.probeTimeout != 3*time.Second {
		t.Fatalf("CLI override failed: %+v", cfg)
	}
	if cfg.probeInterval != 4*time.Second {
		t.Fatalf("probe interval not loaded: %+v", cfg)
	}
	if cfg.bodyLimit != 1234 {
		t.Fatalf("body limit not loaded: %+v", cfg)
	}
}

func TestParseArgsLoadsFlatYAMLConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snet.yaml")
	content := "mode: sniff\ncapture_mode: passive\niface: eth0\nformat: json\ntimeout: 5s\ncount: 7\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := parseArgs([]string{"-config", path})
	if cfg.mode != "sniff" || cfg.captureMode != "passive" || cfg.iface != "eth0" || cfg.format != "json" {
		t.Fatalf("yaml config not loaded: %+v", cfg)
	}
	if cfg.timeout != 5*time.Second || cfg.count != 7 {
		t.Fatalf("yaml duration/int not loaded: %+v", cfg)
	}
}

func TestSelectedProbeTargetsMergesAndDeduplicates(t *testing.T) {
	cfg := config{probeTarget: "example.com:80", probeTargets: "example.org:80, example.com:80,,example.net:80"}
	targets := selectedProbeTargets(cfg)
	want := []string{"example.org:80", "example.com:80", "example.net:80"}
	if len(targets) != len(want) {
		t.Fatalf("targets length mismatch: got %v want %v", targets, want)
	}
	for i := range want {
		if targets[i] != want[i] {
			t.Fatalf("targets mismatch: got %v want %v", targets, want)
		}
	}
}

func TestRunProbeMultipleTargetsAndRounds(t *testing.T) {
	sink := &memorySink{}
	cfg := config{
		mode:          "probe",
		protocols:     "ip",
		probeTargets:  "127.0.0.1,localhost",
		probeTimeout:  time.Second,
		probeInterval: time.Millisecond,
		count:         2,
		bodyLimit:     defaultBodyLimit,
	}
	if err := runProbe(cfg, sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 4 {
		t.Fatalf("expected 4 probe events, got %d: %+v", len(sink.events), sink.events)
	}
	seen := map[string]bool{}
	for _, e := range sink.events {
		if e.Protocol != "IP" || !e.Success {
			t.Fatalf("unexpected probe event: %+v", e)
		}
		seen[e.Domain] = true
	}
	if !seen["127.0.0.1"] || !seen["localhost"] {
		t.Fatalf("targets not probed: %+v", sink.events)
	}
}

func TestProtocolAllowed(t *testing.T) {
	p := &proxyServer{cfg: config{protocols: "http,https"}}
	if !p.protocolAllowed("HTTP") || !p.protocolAllowed("HTTPS") {
		t.Fatal("expected http and https allowed")
	}
	if p.protocolAllowed("MySQL") {
		t.Fatal("expected mysql denied")
	}
}

func TestHTTPSProxyCapturesRequestAndResponseBody(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secure":` + strconvQuote(string(body)) + `}`))
	}))
	defer upstream.Close()

	upstreamTransport := upstream.Client().Transport.(*http.Transport).Clone()
	proxyURL, sink, proxyCACert, stop := startTestProxy(t, upstreamTransport)
	defer stop()

	pool := x509.NewCertPool()
	pool.AddCert(proxyCACert)
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			ServerName: "127.0.0.1",
			MinVersion: tls.VersionTLS12,
		},
	}}

	serverURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "https://"+serverURL.Host+"/secure", strings.NewReader(`{"hello":"https"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d", resp.StatusCode)
	}

	e := sink.last()
	if e.Protocol != "HTTPS" || e.Path != "/secure" {
		t.Fatalf("unexpected event: %+v", e)
	}
	if e.RequestBody != `{"hello":"https"}` {
		t.Fatalf("request body not captured: %q", e.RequestBody)
	}
	if !strings.Contains(e.ResponseBody, `"secure"`) || !strings.Contains(e.ResponseBody, `https`) {
		t.Fatalf("response body not captured: %q", e.ResponseBody)
	}
}

func startTestProxy(t *testing.T, transport *http.Transport) (*url.URL, *memorySink, *x509.Certificate, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tempDir := t.TempDir()
	caCert, caKey, err := loadOrCreateCA(filepath.Join(tempDir, "ca.pem"), filepath.Join(tempDir, "ca-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if transport == nil {
		transport = &http.Transport{DisableCompression: true}
	}
	sink := &memorySink{}
	ctx, cancel := context.WithCancel(context.Background())
	proxy := &proxyServer{
		cfg:       config{protocols: "all", sniffMode: "full", bodyLimit: defaultBodyLimit},
		output:    sink,
		transport: transport,
		caCert:    caCert,
		caKey:     caKey,
		certs:     make(map[string]*tls.Certificate),
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go proxy.handleConn(ctx, conn)
		}
	}()
	proxyURL, err := url.Parse("http://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return proxyURL, sink, caCert, func() {
		cancel()
		_ = listener.Close()
	}
}

func strconvQuote(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func TestParseDNSQuestion(t *testing.T) {
	packet := dnsQueryPacket("example.com")
	if got := parseDNSQuestion(packet); got != "example.com" {
		t.Fatalf("unexpected DNS question %q", got)
	}
}

func TestDetectPayloadEventRecognizesProtocols(t *testing.T) {
	local := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000}
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50000}

	ws := detectPayloadEvent("tcp", local, remote, []byte("GET / HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"), 1024)
	if ws.Protocol != "WebSocket" {
		t.Fatalf("expected WebSocket, got %+v", ws)
	}

	httpEvent := detectPayloadEvent("tcp", local, remote, []byte("GET /hello?x=1 HTTP/1.1\r\nHost: example.com\r\nX-Test: yes\r\n\r\nbody"), 1024)
	if httpEvent.Protocol != "HTTP" || httpEvent.Method != "GET" || httpEvent.Path != "/hello" || httpEvent.Host != "example.com" {
		t.Fatalf("expected HTTP event, got %+v", httpEvent)
	}
	if httpEvent.Query != "x=1" || httpEvent.RequestHeaders["X-Test"][0] != "yes" || httpEvent.RequestBody != "body" {
		t.Fatalf("expected HTTP request info, got %+v", httpEvent)
	}

	httpResponse := detectPayloadEvent("tcp", local, remote, []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello"), 1024)
	if httpResponse.Protocol != "HTTP" || httpResponse.Status != 200 || httpResponse.ResponseHeaders["Content-Type"][0] != "text/plain" || httpResponse.ResponseBody != "hello" {
		t.Fatalf("expected HTTP response info, got %+v", httpResponse)
	}

	amqp := detectPayloadEvent("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5672}, remote, []byte("AMQP\x00\x00\x09\x01"), 1024)
	if amqp.Protocol != "AMQP" {
		t.Fatalf("expected AMQP, got %+v", amqp)
	}

	mysql := detectPayloadEvent("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 3306}, remote, mysqlHandshakePacket("8.0.0-test"), 1024)
	if mysql.Protocol != "MySQL" || mysql.ResponseHeaders["server_version"][0] != "8.0.0-test" {
		t.Fatalf("expected MySQL handshake, got %+v", mysql)
	}

	mysqlQuery := detectPayloadEvent("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 3306}, remote, mysqlQueryPacket("select * from users where id = 1"), 1024)
	if mysqlQuery.Protocol != "MySQL" || mysqlQuery.Stage != "mysql_query" || mysqlQuery.Query != "select * from users where id = 1" {
		t.Fatalf("expected MySQL query, got %+v", mysqlQuery)
	}

	mysqlLogin := detectPayloadEvent("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 3306}, remote, mysqlLoginPacket("app_user"), 1024)
	if mysqlLogin.Protocol != "MySQL" || mysqlLogin.Stage != "mysql_login" || mysqlLogin.Account != "app_user" {
		t.Fatalf("expected MySQL login, got %+v", mysqlLogin)
	}

	dns := detectPayloadEvent("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50000}, dnsQueryPacket("example.com"), 1024)
	if dns.Protocol != "Domain" || dns.Domain != "example.com" {
		t.Fatalf("expected Domain event, got %+v", dns)
	}
}

func TestParseMySQLQueryAndTransaction(t *testing.T) {
	cases := []struct {
		sql         string
		transaction string
	}{
		{sql: "select 1"},
		{sql: "BEGIN", transaction: "begin"},
		{sql: "start transaction", transaction: "begin"},
		{sql: "COMMIT", transaction: "commit"},
		{sql: "rollback", transaction: "rollback"},
		{sql: "SAVEPOINT sp1", transaction: "savepoint"},
		{sql: "RELEASE SAVEPOINT sp1", transaction: "release_savepoint"},
		{sql: "SET autocommit=0", transaction: "set_autocommit_off"},
		{sql: "SET autocommit=1", transaction: "set_autocommit_on"},
	}
	for _, tt := range cases {
		packet := mysqlQueryPacket(tt.sql)
		if got := parseMySQLQuery(packet); got != tt.sql {
			t.Fatalf("query mismatch: got %q want %q", got, tt.sql)
		}
		if got := classifyMySQLTransaction(tt.sql); got != tt.transaction {
			t.Fatalf("transaction mismatch for %q: got %q want %q", tt.sql, got, tt.transaction)
		}
	}
}

func TestProbeTCPUDPAndSocket(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	go func() {
		conn, err := tcpListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 16)
		n, _ := conn.Read(buf)
		_, _ = conn.Write([]byte("echo:" + string(buf[:n])))
	}()
	cfg := config{probeTarget: tcpListener.Addr().String(), probePayload: "hello", probeTimeout: time.Second, bodyLimit: defaultBodyLimit}
	tcpEvent, err := probeTCP(cfg, time.Now())
	if err != nil || tcpEvent.Protocol != "TCP" {
		t.Fatalf("tcp probe failed: event=%+v err=%v", tcpEvent, err)
	}

	// Start a fresh TCP listener for socket probe because previous one accepts once.
	socketListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socketListener.Close()
	go func() {
		conn, err := socketListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 16)
		n, _ := conn.Read(buf)
		_, _ = conn.Write([]byte("echo:" + string(buf[:n])))
	}()
	cfg.probeTarget = socketListener.Addr().String()
	socketEvent, err := probeSocket(cfg, time.Now())
	if err != nil || socketEvent.Protocol != "Socket" || !strings.Contains(socketEvent.Payload, "echo:hello") {
		t.Fatalf("socket probe failed: event=%+v err=%v", socketEvent, err)
	}

	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	go func() {
		buf := make([]byte, 16)
		n, addr, err := udpConn.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = udpConn.WriteTo([]byte("udp:"+string(buf[:n])), addr)
	}()
	cfg.probeTarget = udpConn.LocalAddr().String()
	udpEvent, err := probeUDP(cfg, time.Now())
	if err != nil || udpEvent.Protocol != "UDP" || !strings.Contains(udpEvent.Payload, "udp:hello") {
		t.Fatalf("udp probe failed: event=%+v err=%v", udpEvent, err)
	}
}

func TestProbeWebSocketAMQPMySQLAndHTTP(t *testing.T) {
	wsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			t.Fatalf("missing websocket upgrade")
		}
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	defer wsServer.Close()
	wsURL := "ws" + strings.TrimPrefix(wsServer.URL, "http")
	wsEvent, err := probeWebSocket(config{probeTarget: wsURL, probeTimeout: time.Second, bodyLimit: defaultBodyLimit}, time.Now())
	if err != nil || wsEvent.Protocol != "WebSocket" || wsEvent.Status != http.StatusSwitchingProtocols {
		t.Fatalf("websocket probe failed: event=%+v err=%v", wsEvent, err)
	}

	amqpListener := oneShotTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 8)
		_, _ = io.ReadFull(conn, buf)
		_, _ = conn.Write([]byte("AMQP-OK"))
	})
	amqpEvent, err := probeAMQP(config{probeTarget: amqpListener.Addr().String(), probeTimeout: time.Second, bodyLimit: defaultBodyLimit}, time.Now())
	if err != nil || amqpEvent.Protocol != "AMQP" || !strings.Contains(amqpEvent.Payload, "AMQP-OK") {
		t.Fatalf("amqp probe failed: event=%+v err=%v", amqpEvent, err)
	}

	mysqlListener := oneShotTCPServer(t, func(conn net.Conn) {
		_, _ = conn.Write(mysqlHandshakePacket("5.7-test"))
	})
	mysqlEvent, err := probeMySQL(config{probeTarget: mysqlListener.Addr().String(), probeTimeout: time.Second, bodyLimit: defaultBodyLimit}, time.Now())
	if err != nil || mysqlEvent.Protocol != "MySQL" || mysqlEvent.ResponseHeaders["server_version"][0] != "5.7-test" {
		t.Fatalf("mysql probe failed: event=%+v err=%v", mysqlEvent, err)
	}

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = fmt.Fprintf(w, "got:%s", string(body))
	}))
	defer httpServer.Close()
	httpEvent, err := probeHTTP(config{probeTarget: httpServer.URL, probePayload: "body", probeTimeout: time.Second, bodyLimit: defaultBodyLimit, sniffMode: "full"}, "http", time.Now())
	if err != nil || httpEvent.Protocol != "HTTP" || httpEvent.RequestBody != "body" || !strings.Contains(httpEvent.ResponseBody, "got:body") {
		t.Fatalf("http probe failed: event=%+v err=%v", httpEvent, err)
	}
}

func oneShotTCPServer(t *testing.T, handler func(net.Conn)) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer listener.Close()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		handler(conn)
	}()
	return listener
}

func dnsQueryPacket(domain string) []byte {
	packet := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for label := range strings.SplitSeq(domain, ".") {
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	packet = append(packet, 0, 0, 1, 0, 1)
	return packet
}

func mysqlHandshakePacket(version string) []byte {
	body := append([]byte{10}, []byte(version)...)
	body = append(body, 0, 1, 0, 0, 0)
	packet := make([]byte, 4+len(body))
	packet[0] = byte(len(body))
	packet[1] = byte(len(body) >> 8)
	packet[2] = byte(len(body) >> 16)
	binary.LittleEndian.PutUint32(packet[4:], binary.LittleEndian.Uint32(body[:4]))
	copy(packet[4:], body)
	return packet
}

func mysqlQueryPacket(sql string) []byte {
	body := append([]byte{0x03}, []byte(sql)...)
	packet := make([]byte, 4+len(body))
	packet[0] = byte(len(body))
	packet[1] = byte(len(body) >> 8)
	packet[2] = byte(len(body) >> 16)
	packet[3] = 0
	copy(packet[4:], body)
	return packet
}

func mysqlLoginPacket(account string) []byte {
	body := make([]byte, 32)
	body[0] = 0x85
	body[1] = 0xa6
	body[2] = 0x03
	body[3] = 0x00
	body = append(body, []byte(account)...)
	body = append(body, 0)
	body = append(body, 0) // empty auth response length
	packet := make([]byte, 4+len(body))
	packet[0] = byte(len(body))
	packet[1] = byte(len(body) >> 8)
	packet[2] = byte(len(body) >> 16)
	packet[3] = 1
	copy(packet[4:], body)
	return packet
}
