package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
)

func canonicalProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "dns", "domain":
		return "Domain"
	case "ip":
		return "IP"
	case "tcp":
		return "TCP"
	case "udp":
		return "UDP"
	case "websocket", "web socket", "ws", "wss":
		return "WebSocket"
	case "socket":
		return "Socket"
	case "amqp":
		return "AMQP"
	case "mysql":
		return "MySQL"
	case "http":
		return "HTTP"
	case "https":
		return "HTTPS"
	default:
		return strings.TrimSpace(protocol)
	}
}

func cleanProxyHeaders(header http.Header) {
	for _, name := range []string{"Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Connection", "Keep-Alive"} {
		header.Del(name)
		header.Del(textproto.CanonicalMIMEHeaderKey(name))
	}
}

func cloneHeader(header http.Header) map[string][]string {
	if len(header) == 0 {
		return nil
	}
	copyHeader := make(map[string][]string, len(header))
	for k, values := range header {
		copyHeader[k] = append([]string(nil), values...)
	}
	return copyHeader
}

func normalizedFlowID(a string, b string) string {
	parts := []string{a, b}
	if parts[1] < parts[0] {
		parts[0], parts[1] = parts[1], parts[0]
	}
	sum := sha256.Sum256([]byte(parts[0] + "|" + parts[1]))
	return hex.EncodeToString(sum[:8])
}

func hostnameOnly(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err == nil {
		return host
	}
	return hostport
}

func parseDNSQuestion(packet []byte) string {
	if len(packet) < 13 {
		return ""
	}
	qdCount := binary.BigEndian.Uint16(packet[4:6])
	if qdCount == 0 {
		return ""
	}
	var labels []string
	for i := 12; i < len(packet); {
		length := int(packet[i])
		i++
		if length == 0 {
			break
		}
		if length&0xC0 != 0 || i+length > len(packet) {
			return ""
		}
		labels = append(labels, string(packet[i:i+length]))
		i += length
	}
	return strings.Join(labels, ".")
}

func looksLikeMySQL(payload []byte) bool {
	if len(payload) < 5 {
		return false
	}
	packetLength := int(payload[0]) | int(payload[1])<<8 | int(payload[2])<<16
	return packetLength > 0 && packetLength+4 <= len(payload) && payload[3] < 10
}

func parseMySQLQuery(payload []byte) string {
	body, ok := mysqlPacketBody(payload)
	if !ok || len(body) < 2 || body[0] != 0x03 {
		return ""
	}
	return strings.TrimSpace(string(body[1:]))
}

func parseMySQLAccount(payload []byte) string {
	body, ok := mysqlPacketBody(payload)
	if !ok || len(body) < 33 || body[0] == 0x03 || body[0] == 0x0a {
		return ""
	}
	// Protocol 41 handshake response: capability flags(4), max packet(4), charset(1), filler(23), username(NUL).
	username := body[32:]
	end := bytes.IndexByte(username, 0)
	if end <= 0 {
		return ""
	}
	name := string(username[:end])
	if strings.ContainsAny(name, "\x00\r\n") {
		return ""
	}
	return name
}

func mysqlPacketBody(payload []byte) ([]byte, bool) {
	if len(payload) < 5 {
		return nil, false
	}
	packetLength := int(payload[0]) | int(payload[1])<<8 | int(payload[2])<<16
	if packetLength <= 0 || packetLength+4 > len(payload) {
		return nil, false
	}
	return payload[4 : 4+packetLength], true
}

func classifyMySQLTransaction(sql string) string {
	normalized := strings.ToLower(strings.TrimSpace(strings.TrimRight(sql, ";")))
	if normalized == "" {
		return ""
	}
	fields := strings.Fields(normalized)
	if len(fields) == 0 {
		return ""
	}
	switch fields[0] {
	case "begin":
		return "begin"
	case "commit":
		return "commit"
	case "rollback":
		return "rollback"
	case "savepoint":
		return "savepoint"
	case "release":
		if len(fields) > 1 && fields[1] == "savepoint" {
			return "release_savepoint"
		}
	case "start":
		if len(fields) > 1 && fields[1] == "transaction" {
			return "begin"
		}
	case "set":
		if strings.Contains(normalized, "autocommit") {
			if strings.Contains(normalized, "=0") || strings.Contains(normalized, "= off") || strings.Contains(normalized, "=off") {
				return "set_autocommit_off"
			}
			if strings.Contains(normalized, "=1") || strings.Contains(normalized, "= on") || strings.Contains(normalized, "=on") {
				return "set_autocommit_on"
			}
			return "set_autocommit"
		}
	}
	return ""
}

func parseMySQLServerVersion(payload []byte) string {
	if len(payload) < 6 || payload[4] != 10 {
		return ""
	}
	end := bytes.IndexByte(payload[5:], 0)
	if end < 1 {
		return ""
	}
	return string(payload[5 : 5+end])
}

func fillAddrFields(e *event, source net.Addr, destination net.Addr) {
	e.SourceIP = addrHost(source)
	e.DestinationIP = addrHost(destination)
	e.SourcePort = addrPort(source)
	e.DestinationPort = addrPort(destination)
}

func fillEndpointFields(e *event, source string, destination string) {
	e.SourceIP, e.SourcePort = splitEndpoint(source)
	e.DestinationIP, e.DestinationPort = splitEndpoint(destination)
}

func splitEndpoint(value string) (string, int) {
	host, portValue, err := net.SplitHostPort(value)
	if err != nil {
		return value, 0
	}
	port, _ := strconv.Atoi(portValue)
	return host, port
}

func addrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func addrHost(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addrString(addr))
	if err != nil {
		return addrString(addr)
	}
	return host
}

func addrPort(addr net.Addr) int {
	_, portValue, err := net.SplitHostPort(addrString(addr))
	if err != nil {
		return 0
	}
	port, _ := strconv.Atoi(portValue)
	return port
}

func targetWithDefaultPort(target string, defaultPort string) string {
	host, port, hasPort := splitTarget(target, defaultPort)
	if hasPort {
		return net.JoinHostPort(host, port)
	}
	return net.JoinHostPort(host, defaultPort)
}

func splitTarget(target string, defaultPort string) (string, string, bool) {
	if strings.Contains(target, "://") {
		parsed, err := url.Parse(target)
		if err == nil {
			target = parsed.Host
		}
	}
	host, port, err := net.SplitHostPort(target)
	if err == nil {
		return host, port, true
	}
	if strings.Count(target, ":") > 1 && !strings.HasPrefix(target, "[") {
		return target, defaultPort, false
	}
	return strings.Trim(target, "[]"), defaultPort, false
}

func parseWebSocketTarget(target string) (*url.URL, error) {
	if !strings.Contains(target, "://") {
		target = "ws://" + target
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "ws" && parsed.Scheme != "wss" {
		return nil, fmt.Errorf("unsupported websocket scheme %q", parsed.Scheme)
	}
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return parsed, nil
}
