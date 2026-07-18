package app

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
)

type event struct {
	Timestamp         string              `json:"timestamp"`
	Protocol          string              `json:"protocol"`
	Stage             string              `json:"stage,omitempty"`
	FlowID            string              `json:"flow_id"`
	Target            string              `json:"target,omitempty"`
	SourceIP          string              `json:"source_ip,omitempty"`
	DestinationIP     string              `json:"destination_ip,omitempty"`
	SourcePort        int                 `json:"source_port,omitempty"`
	DestinationPort   int                 `json:"destination_port,omitempty"`
	Length            int                 `json:"length,omitempty"`
	Domain            string              `json:"domain,omitempty"`
	Addresses         []string            `json:"addresses,omitempty"`
	Method            string              `json:"method,omitempty"`
	Scheme            string              `json:"scheme,omitempty"`
	Host              string              `json:"host,omitempty"`
	Account           string              `json:"account,omitempty"`
	Path              string              `json:"path,omitempty"`
	Query             string              `json:"query,omitempty"`
	Transaction       string              `json:"transaction,omitempty"`
	Status            int                 `json:"status,omitempty"`
	RequestHeaders    map[string][]string `json:"request_headers,omitempty"`
	ResponseHeaders   map[string][]string `json:"response_headers,omitempty"`
	RequestBody       string              `json:"request_body,omitempty"`
	ResponseBody      string              `json:"response_body,omitempty"`
	RequestEncoding   string              `json:"request_encoding,omitempty"`
	ResponseEncoding  string              `json:"response_encoding,omitempty"`
	RequestTruncated  bool                `json:"request_truncated,omitempty"`
	ResponseTruncated bool                `json:"response_truncated,omitempty"`
	Payload           string              `json:"payload,omitempty"`
	PayloadEncoding   string              `json:"payload_encoding,omitempty"`
	PayloadTruncated  bool                `json:"payload_truncated,omitempty"`
	Success           bool                `json:"success,omitempty"`
	StageMS           int64               `json:"stage_ms,omitempty"`
	TotalMS           int64               `json:"total_ms,omitempty"`
	Error             string              `json:"error,omitempty"`
}

type bodyCapture struct {
	Value     string
	Encoding  string
	Truncated bool
}

func captureAndReplaceBody(req *http.Request, limit int64) (bodyCapture, error) {
	if req.Body == nil {
		return bodyCapture{}, nil
	}
	defer req.Body.Close()
	data, err := io.ReadAll(req.Body)
	if err != nil {
		return bodyCapture{}, err
	}
	req.Body = io.NopCloser(bytes.NewReader(data))
	req.ContentLength = int64(len(data))
	return encodeBodyForLimit(data, limit), nil
}

func captureResponseBody(resp *http.Response, limit int64) (bodyCaptureWithRaw, error) {
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return bodyCaptureWithRaw{}, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(data))
	capture := encodeBodyForLimit(data, limit)
	return bodyCaptureWithRaw{bodyCapture: capture, data: data}, nil
}

type bodyCaptureWithRaw struct {
	bodyCapture
	data []byte
}

func (b bodyCaptureWithRaw) raw() []byte { return b.data }

func encodeBodyForLimit(data []byte, limit int64) bodyCapture {
	if limit < 0 {
		limit = 0
	}
	truncated := int64(len(data)) > limit
	if truncated {
		data = data[:limit]
	}
	return encodeBody(data, truncated)
}

func encodeBody(data []byte, truncated bool) bodyCapture {
	if len(data) == 0 {
		return bodyCapture{Truncated: truncated}
	}
	if isPrintableText(data) {
		return bodyCapture{Value: string(data), Encoding: "text", Truncated: truncated}
	}
	return bodyCapture{Value: base64.StdEncoding.EncodeToString(data), Encoding: "base64", Truncated: truncated}
}

func isPrintableText(data []byte) bool {
	for _, b := range data {
		if b == '\n' || b == '\r' || b == '\t' {
			continue
		}
		if b < 32 || b == 127 {
			return false
		}
	}
	return true
}

func fillPayload(e *event, payload []byte, limit int64) {
	e.Length = len(payload)
	captured := encodeBodyForLimit(payload, limit)
	e.Payload = captured.Value
	e.PayloadEncoding = captured.Encoding
	e.PayloadTruncated = captured.Truncated
}
