// Package bsndebug provides a generic, pluggable logger for the go-bsn-cloud-client.
// This file provides an adapter for Uber Zap.
package debug

import (
	"go.uber.org/zap"
)

// ZapLogger adapts a zap.Logger to the bsndebug.Logger interface.
type ZapLogger struct {
	L *zap.Logger
}

// Debug logs a debug message with optional fields.
func (z *ZapLogger) Debug(msg string, fields ...any) {
	if z.L == nil {
		return
	}
	zapFields := make([]zap.Field, 0, len(fields)/2)
	for i := 0; i+1 < len(fields); i += 2 {
		key, ok := fields[i].(string)
		if !ok {
			continue
		}
		zapFields = append(zapFields, zap.Any(key, fields[i+1]))
	}
	z.L.Debug(msg, zapFields...)
}
