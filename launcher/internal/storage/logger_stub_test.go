package storage

import (
	"os"

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
