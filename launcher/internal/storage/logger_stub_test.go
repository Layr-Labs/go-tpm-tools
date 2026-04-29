package storage

import (
	"os"
	"sync"

	clogging "cloud.google.com/go/logging"

	"github.com/Layr-Labs/go-tpm-tools/launcher/internal/logging"
)

// discardLogger is a no-op logging.Logger used by tests that don't need to
// inspect log output. The cloud logging dependency is already on the module
// path via encrypted_volume.go's transitive use, so this adds no new deps.
type discardLogger struct{}

var _ logging.Logger = (*discardLogger)(nil)

func (discardLogger) Log(clogging.Severity, string, ...any) {}
func (discardLogger) Info(string, ...any)                   {}
func (discardLogger) Warn(string, ...any)                   {}
func (discardLogger) Error(string, ...any)                  {}
func (discardLogger) SerialConsoleFile() *os.File           { return nil }
func (discardLogger) Close()                                {}

// capturingLogger records Info calls for poller tests that assert on log shape.
// Other levels go to the discard receiver. Concurrent-safe via a mutex
// because the poller goroutine writes and the test goroutine reads.
type capturingLogger struct {
	discardLogger
	mu   sync.Mutex
	info []capturedMsg
}

type capturedMsg struct {
	msg  string
	args []any
}

func (c *capturingLogger) Info(msg string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.info = append(c.info, capturedMsg{msg: msg, args: append([]any(nil), args...)})
}

func (c *capturingLogger) Infos() []capturedMsg {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]capturedMsg, len(c.info))
	copy(out, c.info)
	return out
}
