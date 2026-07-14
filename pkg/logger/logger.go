package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func New(level, format string) *zap.SugaredLogger {
	var cfg zap.Config

	if format == "console" {
		cfg = zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		cfg = zap.NewProductionConfig()
	}

	lvl := zapcore.InfoLevel
	switch level {
	case "debug":
		lvl = zapcore.DebugLevel
	case "warn":
		lvl = zapcore.WarnLevel
	case "error":
		lvl = zapcore.ErrorLevel
	}
	cfg.Level = zap.NewAtomicLevelAt(lvl)

	logger, err := cfg.Build(
		zap.AddCaller(),
		zap.AddCallerSkip(0),
	)
	if err != nil {
		panic("failed to initialize logger: " + err.Error())
	}

	return logger.Sugar()
}
