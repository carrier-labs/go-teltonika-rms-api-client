// Package bsndebug provides a generic, pluggable logger for the go-bsn-cloud-client.
package debug

import "sync"

// Logger is a minimal interface for debug logging.
type Logger interface {
	Debug(msg string, fields ...any)
}

var (
	logger Logger = noopLogger{}
	mu     sync.RWMutex
)

// SetLogger sets the package-level logger. Pass nil to disable logging.
func SetLogger(l Logger) {
	mu.Lock()
	defer mu.Unlock()
	if l == nil {
		logger = noopLogger{}
	} else {
		logger = l
	}
}

// Debug logs a debug message using the configured logger.
func Debug(msg string, fields ...any) {
	mu.RLock()
	defer mu.RUnlock()
	logger.Debug(msg, fields...)
}

type noopLogger struct{}

func (noopLogger) Debug(string, ...any) {}
