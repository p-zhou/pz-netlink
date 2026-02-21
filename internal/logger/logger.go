package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
)

var (
	logger *slog.Logger
	once   sync.Once
)

type textHandler struct {
	opts slog.HandlerOptions
	out  io.Writer
	mu   sync.Mutex
}

func (h *textHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= h.opts.Level.Level()
}

func (h *textHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	ts := r.Time.Format("2006-01-02 15:04:05.000")
	level := r.Level.String()

	var buf []byte
	buf = append(buf, ts...)
	buf = append(buf, " ["...)
	buf = append(buf, level...)
	buf = append(buf, "] "...)
	buf = append(buf, r.Message...)

	r.Attrs(func(a slog.Attr) bool {
		buf = append(buf, ' ')
		buf = append(buf, a.Key...)
		buf = append(buf, '=')
		buf = append(buf, a.Value.String()...)
		return true
	})

	buf = append(buf, '\n')
	_, err := h.out.Write(buf)
	return err
}

func (h *textHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h
}

func (h *textHandler) WithGroup(name string) slog.Handler {
	return h
}

func Init(level string) {
	once.Do(func() {
		handler := &textHandler{
			opts: slog.HandlerOptions{
				Level: parseLevel(level),
			},
			out: os.Stdout,
		}
		logger = slog.New(handler)
	})
}

func parseLevel(level string) slog.Level {
	switch level {
	case "DEBUG":
		return slog.LevelDebug
	case "INFO":
		return slog.LevelInfo
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func Debug(msg string, args ...any) {
	logger.Debug(msg, args...)
}

func Info(msg string, args ...any) {
	logger.Info(msg, args...)
}

func Warn(msg string, args ...any) {
	logger.Warn(msg, args...)
}

func Error(msg string, args ...any) {
	logger.Error(msg, args...)
}

func With(args ...any) *slog.Logger {
	return logger.With(args...)
}
