package app

import (
	"bytes"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var (
	_ = makeIPEvent
	_ = detectPayloadEvent
)

func makeIPEvent(local net.Addr, remote net.Addr, length int) event {
	e := event{
		Timestamp: time.Now().Format(time.RFC3339Nano),
		Protocol:  "IP",
		Stage:     "ip_packet",
		FlowID:    normalizedFlowID(addrString(remote), addrString(local)),
		Length:    length,
		Success:   true,
	}
	fillAddrFields(&e, remote, local)
	return e
}

func makeTransportEvent(protocol string, local net.Addr, remote net.Addr, payload []byte, limit int64) event {
	e := event{
		Timestamp: time.Now().Format(time.RFC3339Nano),
		Protocol:  protocol,
		Stage:     strings.ToLower(protocol) + "_packet",
		FlowID:    normalizedFlowID(addrString(remote), addrString(local)),
		Length:    len(payload),
		Success:   true,
	}
	fillAddrFields(&e, remote, local)
	fillPayload(&e, payload, limit)
	return e
}

func detectPayloadEvent(network string, local net.Addr, remote net.Addr, payload []byte, limit int64) event {
	localPort := addrPort(local)
	remotePort := addrPort(remote)
	lower := strings.ToLower(string(payload))
	switch {
	case network == "udp" && (localPort == 53 || remotePort == 53 || parseDNSQuestion(payload) != ""):
		e := makeTransportEvent("Domain", local, remote, payload, limit)
		e.Stage = "dns_packet"
		e.Domain = parseDNSQuestion(payload)
		return e
	case strings.Contains(lower, "upgrade: websocket"):
		e := makeTransportEvent("WebSocket", local, remote, payload, limit)
		e.Stage = "websocket_upgrade"
		return e
	case looksLikeHTTP(payload):
		e := makeTransportEvent("HTTP", local, remote, payload, limit)
		e.Stage = "http_packet"
		fillHTTPFields(&e, payload)
		return e
	case bytes.HasPrefix(payload, []byte("AMQP")) || localPort == 5672 || remotePort == 5672:
		e := makeTransportEvent("AMQP", local, remote, payload, limit)
		e.Stage = "amqp_packet"
		return e
	case looksLikeMySQL(payload) || localPort == 3306 || remotePort == 3306 || localPort == 33060 || remotePort == 33060:
		e := makeTransportEvent("MySQL", local, remote, payload, limit)
		e.Stage = "mysql_packet"
		if account := parseMySQLAccount(payload); account != "" {
			e.Stage = "mysql_login"
			e.Account = account
		}
		if query := parseMySQLQuery(payload); query != "" {
			e.Stage = "mysql_query"
			e.Query = query
			e.Transaction = classifyMySQLTransaction(query)
		}
		if version := parseMySQLServerVersion(payload); version != "" {
			e.ResponseHeaders = map[string][]string{"server_version": {version}}
		}
		return e
	case network == "tcp":
		e := makeTransportEvent("Socket", local, remote, payload, limit)
		e.Stage = "socket_packet"
		return e
	default:
		return makeTransportEvent("UDP", local, remote, payload, limit)
	}
}

func looksLikeHTTP(payload []byte) bool {
	line := firstLine(payload)
	if strings.HasPrefix(line, "HTTP/1.") || strings.HasPrefix(line, "HTTP/2") {
		return true
	}
	for _, method := range []string{"GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS ", "TRACE ", "CONNECT "} {
		if strings.HasPrefix(line, method) {
			return true
		}
	}
	return false
}

func fillHTTPFields(e *event, payload []byte) {
	line := firstLine(payload)
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return
	}
	if strings.HasPrefix(parts[0], "HTTP/") {
		if len(parts) > 1 {
			status, _ := strconv.Atoi(parts[1])
			e.Status = status
		}
		e.ResponseHeaders, e.ResponseBody, e.ResponseEncoding, e.ResponseTruncated = parseHTTPMessageDetails(payload)
		return
	}
	e.Method = parts[0]
	if len(parts) > 1 {
		e.Path = parts[1]
		if parsed, err := url.Parse(parts[1]); err == nil {
			if parsed.Path != "" {
				e.Path = parsed.Path
			}
			e.Query = parsed.RawQuery
		}
	}
	if host := headerValue(payload, "Host"); host != "" {
		e.Host = host
	}
	e.RequestHeaders, e.RequestBody, e.RequestEncoding, e.RequestTruncated = parseHTTPMessageDetails(payload)
}

func firstLine(payload []byte) string {
	line := string(payload)
	if before, _, ok := strings.Cut(line, "\r\n"); ok {
		return before
	}
	if before, _, ok := strings.Cut(line, "\n"); ok {
		return before
	}
	return line
}

func headerValue(payload []byte, name string) string {
	prefix := strings.ToLower(name) + ":"
	for line := range strings.SplitSeq(string(payload), "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), prefix) {
			return strings.TrimSpace(line[len(prefix):])
		}
	}
	return ""
}

func parseHTTPMessageDetails(payload []byte) (map[string][]string, string, string, bool) {
	text := string(payload)
	head, body, hasBody := strings.Cut(text, "\r\n\r\n")
	if !hasBody {
		head = text
	}
	headers := make(map[string][]string)
	lines := strings.Split(head, "\r\n")
	if len(lines) > 1 {
		for _, line := range lines[1:] {
			name, value, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			name = strings.TrimSpace(name)
			value = strings.TrimSpace(value)
			if name != "" {
				headers[name] = append(headers[name], value)
			}
		}
	}
	if len(headers) == 0 {
		headers = nil
	}
	if !hasBody || body == "" {
		return headers, "", "", false
	}
	captured := encodeBody([]byte(body), false)
	return headers, captured.Value, captured.Encoding, captured.Truncated
}
