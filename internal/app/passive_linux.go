//go:build linux

package app

import (
	"context"
	"encoding/binary"
	"net"
	"syscall"
	"time"
)

const (
	ethPAll  = 0x0003
	ethPIp   = 0x0800
	ethPIpv6 = 0x86DD
)

func runPassiveSniffer(ctx context.Context, cfg config, out sink) error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	if cfg.iface != "" {
		iface, err := net.InterfaceByName(cfg.iface)
		if err != nil {
			return err
		}
		addr := &syscall.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: iface.Index}
		if err := syscall.Bind(fd, addr); err != nil {
			return err
		}
	}

	writer := &proxyServer{cfg: cfg, output: out, stop: func() { _ = syscall.Close(fd) }}
	go func() {
		<-ctx.Done()
		_ = syscall.Close(fd)
	}()

	buf := make([]byte, 65535)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		parsePassiveFrame(writer, buf[:n])
	}
}

func parsePassiveFrame(writer *proxyServer, frame []byte) {
	if len(frame) < 14 {
		return
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	switch etherType {
	case ethPIp:
		parsePassiveIPv4(writer, frame[14:])
	case ethPIpv6:
		// IPv6 metadata support can be added later; skip rather than risk malformed parsing.
	}
}

func parsePassiveIPv4(writer *proxyServer, packet []byte) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen <= 0 || totalLen > len(packet) {
		totalLen = len(packet)
	}
	protocol := packet[9]
	srcIP := net.IP(packet[12:16]).String()
	dstIP := net.IP(packet[16:20]).String()
	payload := packet[ihl:totalLen]
	writer.writeEvent(event{
		Timestamp:     time.Now().Format(time.RFC3339Nano),
		Protocol:      "IP",
		Stage:         "ip_packet",
		FlowID:        normalizedFlowID(srcIP, dstIP),
		SourceIP:      srcIP,
		DestinationIP: dstIP,
		Length:        len(payload),
		Success:       true,
	})
	switch protocol {
	case syscall.IPPROTO_TCP:
		parsePassiveTCP(writer, srcIP, dstIP, payload)
	case syscall.IPPROTO_UDP:
		parsePassiveUDP(writer, srcIP, dstIP, payload)
	}
}

func parsePassiveTCP(writer *proxyServer, srcIP string, dstIP string, segment []byte) {
	if len(segment) < 20 {
		return
	}
	srcPort := int(binary.BigEndian.Uint16(segment[0:2]))
	dstPort := int(binary.BigEndian.Uint16(segment[2:4]))
	dataOffset := int(segment[12]>>4) * 4
	if dataOffset < 20 || len(segment) < dataOffset {
		return
	}
	payload := segment[dataOffset:]
	local := &net.TCPAddr{IP: net.ParseIP(dstIP), Port: dstPort}
	remote := &net.TCPAddr{IP: net.ParseIP(srcIP), Port: srcPort}
	if len(payload) == 0 {
		writer.writeEvent(makeTransportEvent("TCP", local, remote, nil, writer.cfg.bodyLimit))
		return
	}
	e := detectPayloadEvent("tcp", local, remote, payload, writer.cfg.bodyLimit)
	if e.Protocol == "MySQL" {
		if e.Account != "" {
			writer.mysqlAccounts.Store(e.FlowID, e.Account)
		} else if account, ok := writer.mysqlAccounts.Load(e.FlowID); ok {
			e.Account = account.(string)
		}
	}
	writer.writeEvent(e)
}

func parsePassiveUDP(writer *proxyServer, srcIP string, dstIP string, datagram []byte) {
	if len(datagram) < 8 {
		return
	}
	srcPort := int(binary.BigEndian.Uint16(datagram[0:2]))
	dstPort := int(binary.BigEndian.Uint16(datagram[2:4]))
	payload := datagram[8:]
	local := &net.UDPAddr{IP: net.ParseIP(dstIP), Port: dstPort}
	remote := &net.UDPAddr{IP: net.ParseIP(srcIP), Port: srcPort}
	writer.writeEvent(detectPayloadEvent("udp", local, remote, payload, writer.cfg.bodyLimit))
}

func htons(value uint16) uint16 {
	return (value<<8)&0xff00 | value>>8
}
