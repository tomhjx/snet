package app

import (
	"encoding/json"
	"fmt"
	"log/syslog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

type sink interface {
	Write(event) error
	Close() error
}

type stdoutSink struct {
	format string
	fields []string
	mu     sync.Mutex
}

func (s *stdoutSink) Write(e event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.format == "json" {
		line, err := json.Marshal(filterEventMap(e, s.fields))
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(os.Stdout, string(line))
		return err
	}

	_, err := fmt.Fprintln(os.Stdout, textLine(e, s.fields))
	return err
}

func (s *stdoutSink) Close() error { return nil }

type syslogSink struct {
	format string
	fields []string
	writer *syslog.Writer
}

func newSyslogSink(format string, fields []string) (*syslogSink, error) {
	w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "snet")
	if err != nil {
		return nil, err
	}
	return &syslogSink{format: format, fields: fields, writer: w}, nil
}

func (s *syslogSink) Write(e event) error {
	line, err := renderLine(s.format, e, s.fields)
	if err != nil {
		return err
	}
	return s.writer.Info(line)
}

func (s *syslogSink) Close() error { return s.writer.Close() }

type unixSink struct {
	format string
	fields []string
	conn   *net.UnixConn
}

func newUnixSink(path string, format string, fields []string) (*unixSink, error) {
	addr := &net.UnixAddr{Name: path, Net: "unixgram"}
	conn, err := net.DialUnix("unixgram", nil, addr)
	if err != nil {
		return nil, err
	}
	return &unixSink{format: format, fields: fields, conn: conn}, nil
}

func (s *unixSink) Write(e event) error {
	line, err := renderLine(s.format, e, s.fields)
	if err != nil {
		return err
	}
	_, err = s.conn.Write([]byte(line))
	return err
}

func (s *unixSink) Close() error { return s.conn.Close() }

func renderLine(format string, e event, fields []string) (string, error) {
	if format == "json" {
		line, err := json.Marshal(filterEventMap(e, fields))
		return string(line), err
	}
	return textLine(e, fields), nil
}

func textLine(e event, fields []string) string {
	fieldMap := eventTextFields(e)
	ordered := outputFields(fields)
	if len(ordered) == 0 {
		ordered = defaultFieldsForEvent(e)
	}
	var parts []string
	for _, field := range ordered {
		value, ok := fieldMap[field]
		if !ok || value == "" {
			continue
		}
		parts = append(parts, field+"="+value)
	}
	return strings.Join(parts, " ")
}

func openSink(cfg config) (sink, error) {
	fields := outputFieldsFromConfig(cfg.fields)
	switch cfg.output {
	case "stdout":
		return &stdoutSink{format: cfg.format, fields: fields}, nil
	case "syslog":
		return newSyslogSink(cfg.format, fields)
	case "unix":
		return newUnixSink(cfg.outputPath, cfg.format, fields)
	default:
		return nil, fmt.Errorf("unsupported output %q", cfg.output)
	}
}

var defaultOutputFields = []string{
	"timestamp", "protocol", "stage", "flow_id", "target",
	"source_ip", "destination_ip", "source_port", "destination_port",
	"length", "domain", "addresses", "method", "scheme", "host", "account", "path", "query", "transaction", "status",
	"request_headers", "response_headers", "request_body", "response_body", "request_encoding", "response_encoding", "request_truncated", "response_truncated",
	"stage_ms", "total_ms", "error",
}

var defaultProbeFields = append(append([]string{}, defaultOutputFields...), "success")

var allOutputFields = []string{
	"timestamp", "protocol", "stage", "flow_id", "target",
	"source_ip", "destination_ip", "source_port", "destination_port",
	"length", "domain", "addresses", "method", "scheme", "host", "account", "path", "query", "transaction", "status",
	"request_headers", "response_headers", "request_body", "response_body", "request_encoding", "response_encoding", "request_truncated", "response_truncated",
	"payload", "payload_encoding", "payload_truncated", "success", "stage_ms", "total_ms", "error",
}

var defaultMySQLQueryFields = []string{"destination_ip", "destination_port", "account", "query"}

func defaultFieldsForEvent(e event) []string {
	if e.Protocol == "MySQL" && e.Query != "" {
		return defaultMySQLQueryFields
	}
	if strings.HasSuffix(e.Stage, "_probe") {
		return defaultProbeFields
	}
	return defaultOutputFields
}

func outputFieldsFromConfig(value string) []string {
	var fields []string
	for field := range strings.SplitSeq(value, ",") {
		field = strings.TrimSpace(field)
		if field != "" {
			fields = append(fields, field)
		}
	}
	return fields
}

func outputFields(fields []string) []string {
	if len(fields) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(fields))
	var normalized []string
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "all" {
			return allOutputFields
		}
		if field == "" || seen[field] {
			continue
		}
		seen[field] = true
		normalized = append(normalized, field)
	}
	return normalized
}

func filterEventMap(e event, fields []string) map[string]any {
	var all map[string]any
	data, _ := json.Marshal(e)
	_ = json.Unmarshal(data, &all)
	selected := outputFields(fields)
	if len(selected) == 0 {
		selected = defaultFieldsForEvent(e)
	}
	filtered := make(map[string]any, len(selected))
	for _, field := range selected {
		if value, ok := all[field]; ok {
			filtered[field] = value
		}
	}
	return filtered
}

func eventTextFields(e event) map[string]string {
	fields := map[string]string{
		"timestamp":         e.Timestamp,
		"protocol":          e.Protocol,
		"stage":             e.Stage,
		"flow_id":           e.FlowID,
		"target":            e.Target,
		"source_ip":         e.SourceIP,
		"destination_ip":    e.DestinationIP,
		"domain":            e.Domain,
		"method":            e.Method,
		"scheme":            e.Scheme,
		"host":              e.Host,
		"account":           e.Account,
		"path":              e.Path,
		"transaction":       e.Transaction,
		"request_encoding":  e.RequestEncoding,
		"response_encoding": e.ResponseEncoding,
		"payload_encoding":  e.PayloadEncoding,
	}
	if e.Error != "" {
		fields["error"] = strconv.Quote(e.Error)
	}
	if e.SourcePort != 0 {
		fields["source_port"] = strconv.Itoa(e.SourcePort)
	}
	if e.DestinationPort != 0 {
		fields["destination_port"] = strconv.Itoa(e.DestinationPort)
	}
	if e.Length != 0 {
		fields["length"] = strconv.Itoa(e.Length)
	}
	if len(e.Addresses) > 0 {
		fields["addresses"] = strings.Join(e.Addresses, ",")
	}
	if e.Query != "" {
		fields["query"] = strconv.Quote(e.Query)
	}
	if e.Status != 0 {
		fields["status"] = strconv.Itoa(e.Status)
	}
	if len(e.RequestHeaders) > 0 {
		fields["request_headers"] = quoteJSON(e.RequestHeaders)
	}
	if len(e.ResponseHeaders) > 0 {
		fields["response_headers"] = quoteJSON(e.ResponseHeaders)
	}
	if e.RequestBody != "" {
		fields["request_body"] = strconv.Quote(e.RequestBody)
	}
	if e.ResponseBody != "" {
		fields["response_body"] = strconv.Quote(e.ResponseBody)
	}
	if e.RequestTruncated {
		fields["request_truncated"] = "true"
	}
	if e.ResponseTruncated {
		fields["response_truncated"] = "true"
	}
	if e.Payload != "" {
		fields["payload"] = strconv.Quote(e.Payload)
	}
	if e.PayloadTruncated {
		fields["payload_truncated"] = "true"
	}
	if e.Success {
		fields["success"] = "true"
	}
	if e.StageMS != 0 {
		fields["stage_ms"] = strconv.FormatInt(e.StageMS, 10)
	}
	if e.TotalMS != 0 {
		fields["total_ms"] = strconv.FormatInt(e.TotalMS, 10)
	}
	return fields
}

func quoteJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return strconv.Quote(string(data))
}
