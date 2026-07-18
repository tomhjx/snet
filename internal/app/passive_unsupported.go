//go:build !linux

package app

import (
	"context"
	"fmt"
	"runtime"
)

func runPassiveSniffer(ctx context.Context, cfg config, out sink) error {
	_ = ctx
	_ = cfg
	_ = out
	return fmt.Errorf("passive sniff is supported on Linux only; current OS: %s", runtime.GOOS)
}
