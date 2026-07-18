package app

import (
	"bufio"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type proxyServer struct {
	cfg           config
	output        sink
	transport     *http.Transport
	caCert        *x509.Certificate
	caKey         *rsa.PrivateKey
	certMu        sync.Mutex
	certs         map[string]*tls.Certificate
	events        atomic.Int64
	flowTimes     sync.Map
	mysqlAccounts sync.Map
	stopOnce      sync.Once
	stop          func()
}

type flowTime struct {
	first time.Time
	last  time.Time
}

func (p *proxyServer) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	select {
	case <-ctx.Done():
		return
	default:
	}
	req, err := http.ReadRequest(reader)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			p.emitError(conn.RemoteAddr().String(), "", err)
		}
		return
	}
	if strings.EqualFold(req.Method, http.MethodConnect) {
		p.handleConnect(ctx, conn, req)
		return
	}
	p.emitError(conn.RemoteAddr().String(), req.Host, errors.New("proxy capture mode only supports HTTPS CONNECT; use passive mode for plaintext HTTP"))
	_, _ = io.WriteString(conn, "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
}

func (p *proxyServer) handleConnect(ctx context.Context, rawConn net.Conn, connectReq *http.Request) {
	targetHost := connectReq.Host
	if _, err := io.WriteString(rawConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	host := hostnameOnly(targetHost)
	cert, err := p.certForHost(host)
	if err != nil {
		p.emitError(rawConn.RemoteAddr().String(), targetHost, err)
		return
	}
	tlsConn := tls.Server(rawConn, &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12})
	if err := tlsConn.Handshake(); err != nil {
		p.emitError(rawConn.RemoteAddr().String(), targetHost, err)
		return
	}

	reader := bufio.NewReader(tlsConn)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		req, err := http.ReadRequest(reader)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				p.emitError(rawConn.RemoteAddr().String(), targetHost, err)
			}
			return
		}
		if req.URL == nil {
			req.URL = &url.URL{}
		}
		req.URL.Scheme = "https"
		req.URL.Host = targetHost
		if req.Host == "" {
			req.Host = targetHost
		}
		if err := p.forwardAndWrite(tlsConn, req, "HTTPS", rawConn.RemoteAddr().String(), targetHost); err != nil {
			p.emitError(rawConn.RemoteAddr().String(), targetHost, err)
			return
		}
		if req.Close {
			return
		}
	}
}

func (p *proxyServer) forwardAndWrite(client net.Conn, req *http.Request, protocol string, source string, destination string) error {
	requestBody, err := captureAndReplaceBody(req, p.cfg.bodyLimit)
	if err != nil {
		return err
	}
	cleanProxyHeaders(req.Header)
	req.RequestURI = ""
	req.RemoteAddr = source
	req.Close = false

	start := time.Now()
	resp, err := p.transport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	responseBody, err := captureResponseBody(resp, p.cfg.bodyLimit)
	if err != nil {
		return err
	}
	resp.Header.Del("Content-Length")
	resp.ContentLength = int64(len(responseBody.raw()))
	resp.Close = false

	e := p.makeEvent(protocol, source, destination, req, resp, requestBody, responseBody, start)
	p.writeEvent(e)

	return resp.Write(client)
}

func (p *proxyServer) makeEvent(protocol string, source string, destination string, req *http.Request, resp *http.Response, requestBody bodyCapture, responseBody bodyCaptureWithRaw, start time.Time) event {
	now := time.Now()
	flowID := normalizedFlowID(source, destination)
	stageMS, totalMS := p.timings(flowID, now)
	e := event{
		Timestamp:         now.Format(time.RFC3339Nano),
		Protocol:          protocol,
		Stage:             strings.ToLower(protocol) + "_response",
		FlowID:            flowID,
		Target:            destination,
		Method:            req.Method,
		Scheme:            req.URL.Scheme,
		Host:              req.URL.Host,
		Path:              req.URL.Path,
		Query:             req.URL.RawQuery,
		Status:            resp.StatusCode,
		RequestHeaders:    cloneHeader(req.Header),
		ResponseHeaders:   cloneHeader(resp.Header),
		RequestBody:       requestBody.Value,
		ResponseBody:      responseBody.Value,
		RequestEncoding:   requestBody.Encoding,
		ResponseEncoding:  responseBody.Encoding,
		RequestTruncated:  requestBody.Truncated,
		ResponseTruncated: responseBody.Truncated,
		StageMS:           stageMS,
		TotalMS:           totalMS,
	}
	if req.URL.Path == "" {
		e.Path = "/"
	}
	fillEndpointFields(&e, source, destination)
	if p.cfg.sniffMode == "timing" {
		e.Method = ""
		e.Scheme = ""
		e.Host = ""
		e.Path = ""
		e.Query = ""
		e.Status = 0
		e.RequestHeaders = nil
		e.ResponseHeaders = nil
		e.RequestBody = ""
		e.ResponseBody = ""
		e.RequestEncoding = ""
		e.ResponseEncoding = ""
		e.RequestTruncated = false
		e.ResponseTruncated = false
	}
	if p.cfg.sniffMode == "content" {
		e.StageMS = 0
		e.TotalMS = 0
	} else if e.StageMS == 0 {
		e.StageMS = time.Since(start).Milliseconds()
	}
	return e
}

func (p *proxyServer) timings(flowID string, now time.Time) (int64, int64) {
	value, _ := p.flowTimes.LoadOrStore(flowID, &flowTime{first: now, last: now})
	ft := value.(*flowTime)
	stage := now.Sub(ft.last).Milliseconds()
	total := now.Sub(ft.first).Milliseconds()
	ft.last = now
	return stage, total
}

func (p *proxyServer) writeEvent(e event) {
	if !p.protocolAllowed(e.Protocol) {
		return
	}
	if p.cfg.count > 0 && p.events.Load() >= p.cfg.count {
		return
	}
	if err := p.output.Write(e); err != nil {
		log.Printf("write output: %v", err)
	}
	if p.cfg.count > 0 && p.events.Add(1) >= p.cfg.count {
		p.stopOnce.Do(func() {
			if p.stop != nil {
				p.stop()
			}
		})
	}
}

func (p *proxyServer) emitError(source string, destination string, err error) {
	if err == nil {
		return
	}
	e := event{
		Timestamp: time.Now().Format(time.RFC3339Nano),
		Protocol:  "Socket",
		Stage:     "error",
		FlowID:    normalizedFlowID(source, destination),
		Target:    destination,
		Error:     err.Error(),
	}
	fillEndpointFields(&e, source, destination)
	p.writeEvent(e)
}

func (p *proxyServer) protocolAllowed(protocol string) bool {
	allow := strings.TrimSpace(strings.ToLower(p.cfg.protocols))
	if allow == "" || allow == "all" {
		return true
	}
	protocol = canonicalProtocol(protocol)
	for part := range strings.SplitSeq(allow, ",") {
		name := canonicalProtocol(part)
		if name == protocol {
			return true
		}
	}
	return false
}
