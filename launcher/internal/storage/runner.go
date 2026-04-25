// Package storage: command execution abstraction for testability.
package storage

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// commandRunner runs an external command and returns its combined stdout.
// Stderr is surfaced inside the returned error on non-zero exit.
// This indirection lets tests inject fakes without spawning real subprocesses.
type commandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// execRunner is the production implementation backed by os/exec.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("%s %v: %w: %s", name, args, err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// defaultRunner is the package-level runner used by production code.
// Tests construct their own runners and pass them explicitly.
var defaultRunner commandRunner = execRunner{}
