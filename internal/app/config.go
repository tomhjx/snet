package app

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const defaultBodyLimit = 64 * 1024

type config struct {
	configPath    string
	mode          string
	captureMode   string
	listen        string
	iface         string
	format        string
	fields        string
	output        string
	outputPath    string
	protocols     string
	sniffMode     string
	probeTarget   string
	probeTargets  string
	probePayload  string
	probeTimeout  time.Duration
	probeInterval time.Duration
	count         int64
	timeout       time.Duration
	caCertPath    string
	caKeyPath     string
	bodyLimit     int64
}

func parseFlags() config {
	return parseArgs(os.Args[1:])
}

func parseArgs(args []string) config {
	defaults := defaultConfig()
	cli := defaults
	flags := newFlagSet(&cli)
	_ = flags.Parse(args)

	final := defaults
	if cli.configPath != "" {
		loaded, err := loadConfigFile(cli.configPath, final)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load config %s: %v\n", cli.configPath, err)
			os.Exit(2)
		}
		final = loaded
		final.configPath = cli.configPath
	}

	flags.Visit(func(f *flag.Flag) {
		applyFlagValue(&final, f.Name, f.Value.String())
	})
	return final
}

func defaultConfig() config {
	home, _ := os.UserHomeDir()
	caDir := filepath.Join(home, ".snet")
	return config{
		mode:         "sniff",
		captureMode:  "passive",
		listen:       ":8080",
		format:       "text",
		fields:       "",
		output:       "stdout",
		outputPath:   "/tmp/cnet.sock",
		protocols:    "all",
		sniffMode:    "content",
		probePayload: "ping",
		probeTimeout: 5 * time.Second,
		caCertPath:   filepath.Join(caDir, "snet-ca.pem"),
		caKeyPath:    filepath.Join(caDir, "snet-ca-key.pem"),
		bodyLimit:    defaultBodyLimit,
	}
}

func newFlagSet(cfg *config) *flag.FlagSet {
	flags := flag.NewFlagSet("snet", flag.ExitOnError)
	flags.StringVar(&cfg.configPath, "config", cfg.configPath, "config file path (JSON or flat YAML)")
	flags.StringVar(&cfg.mode, "mode", cfg.mode, "run mode: sniff or probe")
	flags.StringVar(&cfg.captureMode, "capture-mode", cfg.captureMode, "sniff capture mode: passive or proxy")
	flags.StringVar(&cfg.listen, "listen", cfg.listen, "HTTPS proxy listen address")
	flags.StringVar(&cfg.iface, "iface", cfg.iface, "network interface name kept for CLI compatibility")
	flags.StringVar(&cfg.iface, "i", cfg.iface, "alias of -iface")
	flags.StringVar(&cfg.format, "format", cfg.format, "output format: text or json")
	flags.StringVar(&cfg.format, "f", cfg.format, "alias of -format")
	flags.StringVar(&cfg.fields, "fields", cfg.fields, "comma separated output fields; empty means all fields")
	flags.StringVar(&cfg.output, "output", cfg.output, "output target: stdout, syslog, unix")
	flags.StringVar(&cfg.output, "o", cfg.output, "alias of -output")
	flags.StringVar(&cfg.outputPath, "output-path", cfg.outputPath, "output path for unix datagram socket")
	flags.StringVar(&cfg.outputPath, "p", cfg.outputPath, "alias of -output-path")
	flags.StringVar(&cfg.protocols, "protocols", cfg.protocols, "comma separated protocol allowlist")
	flags.StringVar(&cfg.protocols, "P", cfg.protocols, "alias of -protocols")
	flags.StringVar(&cfg.sniffMode, "sniff-mode", cfg.sniffMode, "content, full, or timing")
	flags.StringVar(&cfg.sniffMode, "m", cfg.sniffMode, "alias of -sniff-mode")
	flags.StringVar(&cfg.probeTarget, "probe-target", cfg.probeTarget, "probe target host, address, or URL")
	flags.StringVar(&cfg.probeTarget, "target", cfg.probeTarget, "alias of -probe-target")
	flags.StringVar(&cfg.probeTargets, "probe-targets", cfg.probeTargets, "comma separated probe targets")
	flags.StringVar(&cfg.probeTargets, "targets", cfg.probeTargets, "alias of -probe-targets")
	flags.StringVar(&cfg.probePayload, "probe-payload", cfg.probePayload, "payload used by socket, udp, websocket, amqp, and mysql probes")
	flags.DurationVar(&cfg.probeTimeout, "probe-timeout", cfg.probeTimeout, "per-protocol probe timeout")
	flags.DurationVar(&cfg.probeInterval, "probe-interval", cfg.probeInterval, "interval between probe rounds; 0 means run once")
	flags.Int64Var(&cfg.count, "count", cfg.count, "event count before exit; 0 means unlimited")
	flags.Int64Var(&cfg.count, "c", cfg.count, "alias of -count")
	flags.DurationVar(&cfg.timeout, "timeout", cfg.timeout, "run duration; 0 means unlimited")
	flags.DurationVar(&cfg.timeout, "t", cfg.timeout, "alias of -timeout")
	flags.StringVar(&cfg.caCertPath, "ca-cert", cfg.caCertPath, "root CA certificate path for HTTPS MITM")
	flags.StringVar(&cfg.caKeyPath, "ca-key", cfg.caKeyPath, "root CA private key path for HTTPS MITM")
	flags.Int64Var(&cfg.bodyLimit, "body-limit", cfg.bodyLimit, "max captured request/response body bytes per direction")
	return flags
}

type fileConfig struct {
	Mode          *string `json:"mode"`
	CaptureMode   *string `json:"capture_mode"`
	Listen        *string `json:"listen"`
	Iface         *string `json:"iface"`
	Format        *string `json:"format"`
	Fields        *string `json:"fields"`
	Output        *string `json:"output"`
	OutputPath    *string `json:"output_path"`
	Protocols     *string `json:"protocols"`
	SniffMode     *string `json:"sniff_mode"`
	ProbeTarget   *string `json:"probe_target"`
	ProbeTargets  *string `json:"probe_targets"`
	ProbePayload  *string `json:"probe_payload"`
	ProbeTimeout  *string `json:"probe_timeout"`
	ProbeInterval *string `json:"probe_interval"`
	Count         *int64  `json:"count"`
	Timeout       *string `json:"timeout"`
	CACertPath    *string `json:"ca_cert"`
	CAKeyPath     *string `json:"ca_key"`
	BodyLimit     *int64  `json:"body_limit"`
}

func loadConfigFile(path string, base config) (config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return base, err
	}
	var fc fileConfig
	if err := json.Unmarshal(data, &fc); err != nil {
		parsed, yamlErr := parseFlatYAML(data)
		if yamlErr != nil {
			return base, fmt.Errorf("parse JSON failed: %v; parse YAML failed: %v", err, yamlErr)
		}
		fc = parsed
	}
	return applyFileConfig(base, fc)
}

func applyFileConfig(cfg config, fc fileConfig) (config, error) {
	if fc.Mode != nil {
		cfg.mode = *fc.Mode
	}
	if fc.CaptureMode != nil {
		cfg.captureMode = *fc.CaptureMode
	}
	if fc.Listen != nil {
		cfg.listen = *fc.Listen
	}
	if fc.Iface != nil {
		cfg.iface = *fc.Iface
	}
	if fc.Format != nil {
		cfg.format = *fc.Format
	}
	if fc.Fields != nil {
		cfg.fields = *fc.Fields
	}
	if fc.Output != nil {
		cfg.output = *fc.Output
	}
	if fc.OutputPath != nil {
		cfg.outputPath = *fc.OutputPath
	}
	if fc.Protocols != nil {
		cfg.protocols = *fc.Protocols
	}
	if fc.SniffMode != nil {
		cfg.sniffMode = *fc.SniffMode
	}
	if fc.ProbeTarget != nil {
		cfg.probeTarget = *fc.ProbeTarget
	}
	if fc.ProbeTargets != nil {
		cfg.probeTargets = *fc.ProbeTargets
	}
	if fc.ProbePayload != nil {
		cfg.probePayload = *fc.ProbePayload
	}
	if fc.ProbeTimeout != nil {
		d, err := time.ParseDuration(*fc.ProbeTimeout)
		if err != nil {
			return cfg, err
		}
		cfg.probeTimeout = d
	}
	if fc.ProbeInterval != nil {
		d, err := time.ParseDuration(*fc.ProbeInterval)
		if err != nil {
			return cfg, err
		}
		cfg.probeInterval = d
	}
	if fc.Count != nil {
		cfg.count = *fc.Count
	}
	if fc.Timeout != nil {
		d, err := time.ParseDuration(*fc.Timeout)
		if err != nil {
			return cfg, err
		}
		cfg.timeout = d
	}
	if fc.CACertPath != nil {
		cfg.caCertPath = *fc.CACertPath
	}
	if fc.CAKeyPath != nil {
		cfg.caKeyPath = *fc.CAKeyPath
	}
	if fc.BodyLimit != nil {
		cfg.bodyLimit = *fc.BodyLimit
	}
	return cfg, nil
}

func parseFlatYAML(data []byte) (fileConfig, error) {
	values := map[string]string{}
	for rawLine := range strings.SplitSeq(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return fileConfig{}, fmt.Errorf("invalid line %q", rawLine)
		}
		values[strings.TrimSpace(key)] = trimConfigValue(value)
	}
	return fileConfigFromMap(values)
}

func trimConfigValue(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, "'\"")
	return value
}

func fileConfigFromMap(values map[string]string) (fileConfig, error) {
	var fc fileConfig
	for key, value := range values {
		if err := setFileConfigValue(&fc, key, value); err != nil {
			return fc, err
		}
	}
	return fc, nil
}

func setFileConfigValue(fc *fileConfig, key string, value string) error {
	normalized := strings.ReplaceAll(strings.TrimSpace(key), "-", "_")
	str := func(v string) *string { return &v }
	int64Ptr := func(v string) (*int64, error) { n, err := strconv.ParseInt(v, 10, 64); return &n, err }
	switch normalized {
	case "mode":
		fc.Mode = str(value)
	case "capture_mode":
		fc.CaptureMode = str(value)
	case "listen":
		fc.Listen = str(value)
	case "iface":
		fc.Iface = str(value)
	case "format":
		fc.Format = str(value)
	case "fields":
		fc.Fields = str(value)
	case "output":
		fc.Output = str(value)
	case "output_path":
		fc.OutputPath = str(value)
	case "protocols":
		fc.Protocols = str(value)
	case "sniff_mode":
		fc.SniffMode = str(value)
	case "probe_target":
		fc.ProbeTarget = str(value)
	case "probe_targets":
		fc.ProbeTargets = str(value)
	case "probe_payload":
		fc.ProbePayload = str(value)
	case "probe_timeout":
		fc.ProbeTimeout = str(value)
	case "probe_interval":
		fc.ProbeInterval = str(value)
	case "count":
		n, err := int64Ptr(value)
		if err != nil {
			return err
		}
		fc.Count = n
	case "timeout":
		fc.Timeout = str(value)
	case "ca_cert":
		fc.CACertPath = str(value)
	case "ca_key":
		fc.CAKeyPath = str(value)
	case "body_limit":
		n, err := int64Ptr(value)
		if err != nil {
			return err
		}
		fc.BodyLimit = n
	default:
		return fmt.Errorf("unknown config key %q", key)
	}
	return nil
}

func applyFlagValue(cfg *config, name string, value string) {
	key := strings.ReplaceAll(name, "-", "_")
	switch key {
	case "f":
		key = "format"
	case "o":
		key = "output"
	case "p":
		key = "output_path"
	case "P":
		key = "protocols"
	case "m":
		key = "sniff_mode"
	case "c":
		key = "count"
	case "t":
		key = "timeout"
	case "target":
		key = "probe_target"
	case "targets":
		key = "probe_targets"
	case "i":
		key = "iface"
	case "config":
		cfg.configPath = value
		return
	}
	fc, err := fileConfigFromMap(map[string]string{key: value})
	if err != nil {
		return
	}
	updated, err := applyFileConfig(*cfg, fc)
	if err != nil {
		return
	}
	*cfg = updated
}
