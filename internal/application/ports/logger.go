package ports

// Logger is a structured logger interface. Kept deliberately small:
// production wires zap.Logger; tests can use a no-op.
type Logger interface {
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
}

// Field is one key/value pair for structured logging.
type Field struct {
	Key   string
	Value any
}

// F is a tiny constructor for log fields, used to keep call sites compact:
//
//	logger.Info("scan started", ports.F("scanner", name), ports.F("path", p))
func F(k string, v any) Field { return Field{Key: k, Value: v} }
