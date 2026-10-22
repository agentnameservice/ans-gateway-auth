package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/agentnameservice/ans-gateway-auth/config"
)

const (
	exitOK      = 0
	exitRuntime = 1
	exitUsage   = 2

	envConfig     = "ANS_AUTHZ_CONFIG"
	envGRPCListen = "ANS_AUTHZ_GRPC_LISTEN"
	envHTTPListen = "ANS_AUTHZ_HTTP_LISTEN"
	envLogLevel   = "ANS_AUTHZ_LOG_LEVEL"
)

// run parses flags, loads the configuration and serves until ctx is done.
// Flags win over environment variables; both only touch operational settings.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ans-authz", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", os.Getenv(envConfig), "path to the YAML configuration ("+envConfig+")")
	grpcListen := fs.String("grpc-listen", "", "ext_authz gRPC listen address, overrides grpc.listen ("+envGRPCListen+")")
	httpListen := fs.String("http-listen", "", "health and metrics listen address, overrides httpListen ("+envHTTPListen+")")
	logLevel := fs.String("log-level", "", "debug, info, warn or error, overrides logLevel ("+envLogLevel+")")
	check := fs.Bool("check", false, "load and validate the configuration, then exit")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *showVersion {
		fmt.Fprintln(stdout, "ans-authz", version)
		return exitOK
	}
	if *configPath == "" {
		fmt.Fprintln(stderr, "ans-authz: --config or "+envConfig+" is required")
		return exitUsage
	}

	cfg, err := config.Load(*configPath, config.Overrides{
		GRPCListen: firstNonEmpty(*grpcListen, os.Getenv(envGRPCListen)),
		HTTPListen: firstNonEmpty(*httpListen, os.Getenv(envHTTPListen)),
		LogLevel:   firstNonEmpty(*logLevel, os.Getenv(envLogLevel)),
	})
	if err != nil {
		fmt.Fprintln(stderr, "ans-authz:", err)
		return exitUsage
	}
	if *check {
		if _, tlsErr := serverTLS(cfg); tlsErr != nil {
			fmt.Fprintln(stderr, "ans-authz:", tlsErr)
			return exitUsage
		}
		fmt.Fprintln(stdout, "configuration OK")
		for _, w := range cfg.Warnings() {
			fmt.Fprintln(stdout, "warning:", w)
		}
		return exitOK
	}

	logger := newLogger(stderr, cfg.LogLevel)
	for _, w := range cfg.Warnings() {
		logger.WarnContext(ctx, w)
	}
	a, err := newApp(ctx, cfg, logger)
	if err != nil {
		logger.ErrorContext(ctx, "startup failed", "error", err)
		return exitRuntime
	}
	if err := a.Start(ctx); err != nil {
		logger.ErrorContext(ctx, "startup failed", "error", err)
		return exitRuntime
	}
	logger.InfoContext(ctx, "ans-authz serving", "version", version, "grpc", a.GRPCAddr(), "http", a.HTTPAddr(),
		"replay", cfg.Replay.Type, "transparency_logs", len(cfg.TransparencyLogs))
	if err := a.Wait(); err != nil {
		logger.ErrorContext(ctx, "server failed", "error", err)
		return exitRuntime
	}
	logger.InfoContext(ctx, "ans-authz stopped")
	return exitOK
}

func newLogger(w io.Writer, level string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lvl}))
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
