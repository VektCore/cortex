package logging

import (
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/vektcore/cortex/internal/application/ports"
)

// Logger wraps zap.Logger and implements ports.Logger.
type Logger struct {
	z *zap.Logger
}

// New builds a production Logger with the given level string
// ("debug", "info", "warn", "error"). Defaults to "info" on unrecognised input.
func New(level string) (*Logger, error) {
	var lvl zapcore.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = zapcore.InfoLevel
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.Encoding = "console"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	cfg.DisableCaller = true
	cfg.DisableStacktrace = true

	z, err := cfg.Build()
	if err != nil {
		return nil, fmt.Errorf("build logger: %w", err)
	}
	return &Logger{z: z}, nil
}

// NewNop returns a no-op logger. Useful in tests or quiet mode.
func NewNop() *Logger { return &Logger{z: zap.NewNop()} }

func (l *Logger) Debug(msg string, fields ...ports.Field) {
	l.z.Debug(msg, toZap(fields)...)
}
func (l *Logger) Info(msg string, fields ...ports.Field) {
	l.z.Info(msg, toZap(fields)...)
}
func (l *Logger) Warn(msg string, fields ...ports.Field) {
	l.z.Warn(msg, toZap(fields)...)
}
func (l *Logger) Error(msg string, fields ...ports.Field) {
	l.z.Error(msg, toZap(fields)...)
}

// Sync flushes any buffered log entries. Call on shutdown.
func (l *Logger) Sync() { _ = l.z.Sync() }

func toZap(fields []ports.Field) []zap.Field {
	out := make([]zap.Field, len(fields))
	for i, f := range fields {
		out[i] = zap.Any(f.Key, f.Value)
	}
	return out
}
