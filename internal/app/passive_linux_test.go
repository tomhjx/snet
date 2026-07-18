//go:build linux

package app

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestPassiveIPv4TCPHTTPFrame(t *testing.T) {
	sink := &memorySink{}
	writer := &proxyServer{cfg: config{protocols: "all", bodyLimit: defaultBodyLimit}, output: sink}
	payload := []byte("GET /passive HTTP/1.1\r\nHost: example.com\r\n\r\n")
	frame := ethernetIPv4TCPFrame("10.0.0.1", "10.0.0.2", 54321, 80, payload)

	parsePassiveFrame(writer, frame)

	if len(sink.events) < 2 {
		t.Fatalf("expected IP and HTTP events, got %+v", sink.events)
	}
	if sink.events[0].Protocol != "IP" || sink.events[0].SourceIP != "10.0.0.1" || sink.events[0].DestinationIP != "10.0.0.2" {
		t.Fatalf("unexpected IP event: %+v", sink.events[0])
	}
	httpEvent := sink.events[1]
	if httpEvent.Protocol != "HTTP" || httpEvent.Method != "GET" || httpEvent.Path != "/passive" || httpEvent.Host != "example.com" {
		t.Fatalf("unexpected passive HTTP-over-TCP event: %+v", httpEvent)
	}
	if httpEvent.SourcePort != 54321 || httpEvent.DestinationPort != 80 {
		t.Fatalf("unexpected TCP ports: %+v", httpEvent)
	}
}

func TestPassiveIPv4UDPDNSFrame(t *testing.T) {
	sink := &memorySink{}
	writer := &proxyServer{cfg: config{protocols: "all", bodyLimit: defaultBodyLimit}, output: sink}
	payload := dnsQueryPacket("example.com")
	frame := ethernetIPv4UDPFrame("10.0.0.1", "8.8.8.8", 54321, 53, payload)

	parsePassiveFrame(writer, frame)

	if len(sink.events) < 2 {
		t.Fatalf("expected IP and DNS events, got %+v", sink.events)
	}
	dnsEvent := sink.events[1]
	if dnsEvent.Protocol != "Domain" || dnsEvent.Domain != "example.com" {
		t.Fatalf("unexpected passive DNS-over-UDP event: %+v", dnsEvent)
	}
	if dnsEvent.SourcePort != 54321 || dnsEvent.DestinationPort != 53 {
		t.Fatalf("unexpected UDP ports: %+v", dnsEvent)
	}
}

func TestPassiveIPv4TCPMySQLQueryFrame(t *testing.T) {
	sink := &memorySink{}
	writer := &proxyServer{cfg: config{protocols: "all", bodyLimit: defaultBodyLimit}, output: sink}
	payload := mysqlQueryPacket("BEGIN")
	frame := ethernetIPv4TCPFrame("10.0.0.1", "10.0.0.2", 54321, 3306, payload)

	parsePassiveFrame(writer, frame)

	if len(sink.events) < 2 {
		t.Fatalf("expected IP and MySQL events, got %+v", sink.events)
	}
	mysqlEvent := sink.events[1]
	if mysqlEvent.Protocol != "MySQL" || mysqlEvent.Stage != "mysql_query" || mysqlEvent.Query != "BEGIN" || mysqlEvent.Transaction != "begin" {
		t.Fatalf("unexpected passive MySQL query event: %+v", mysqlEvent)
	}
}

func TestPassiveIPv4TCPMySQLAccountAttachedToQuery(t *testing.T) {
	sink := &memorySink{}
	writer := &proxyServer{cfg: config{protocols: "all", bodyLimit: defaultBodyLimit}, output: sink}
	login := ethernetIPv4TCPFrame("10.0.0.1", "10.0.0.2", 54321, 3306, mysqlLoginPacket("app_user"))
	query := ethernetIPv4TCPFrame("10.0.0.1", "10.0.0.2", 54321, 3306, mysqlQueryPacket("select 1"))

	parsePassiveFrame(writer, login)
	parsePassiveFrame(writer, query)

	last := sink.last()
	if last.Protocol != "MySQL" || last.Query != "select 1" || last.Account != "app_user" {
		t.Fatalf("expected account attached to MySQL query, got %+v", last)
	}
}

func ethernetIPv4TCPFrame(src string, dst string, srcPort int, dstPort int, payload []byte) []byte {
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(tcpHeader[2:4], uint16(dstPort))
	tcpHeader[12] = 5 << 4
	return ethernetIPv4Frame(6, src, dst, append(tcpHeader, payload...))
}

func ethernetIPv4UDPFrame(src string, dst string, srcPort int, dstPort int, payload []byte) []byte {
	udpHeader := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHeader[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(udpHeader[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(len(udpHeader)+len(payload)))
	return ethernetIPv4Frame(17, src, dst, append(udpHeader, payload...))
}

func ethernetIPv4Frame(protocol byte, src string, dst string, payload []byte) []byte {
	ethernet := make([]byte, 14)
	binary.BigEndian.PutUint16(ethernet[12:14], ethPIp)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)+len(payload)))
	ip[8] = 64
	ip[9] = protocol
	copy(ip[12:16], net.ParseIP(src).To4())
	copy(ip[16:20], net.ParseIP(dst).To4())
	frame := append(ethernet, ip...)
	frame = append(frame, payload...)
	return frame
}
