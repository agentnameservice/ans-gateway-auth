package main

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRunUsage(t *testing.T) {
	tr := newTrust(t)
	valid := writeConfig(t, configYAML(pinnedTL(tr.line)))
	slow := writeConfig(t, configYAML(pinnedTL(tr.line), "checkTimeout: 2s"))
	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "version", args: []string{"--version"}, wantCode: exitOK, wantStdout: "ans-authz dev"},
		{name: "unknown flag", args: []string{"--bogus"}, wantCode: exitUsage, wantStderr: "flag provided but not defined"},
		{name: "missing config", args: nil, wantCode: exitUsage, wantStderr: "--config or ANS_AUTHZ_CONFIG is required"},
		{name: "unreadable config", args: []string{"--config", "/nonexistent/ans-authz.yaml"}, wantCode: exitUsage, wantStderr: "ans-authz: config:"},
		{name: "check valid", args: []string{"--config", valid, "--check"}, wantCode: exitOK, wantStdout: "configuration OK"},
		{name: "check warns on a long checkTimeout", args: []string{"--config", slow, "--check"}, wantCode: exitOK, wantStdout: "warning: checkTimeout 2s"},
		{name: "config from environment", args: []string{"--check"}, env: map[string]string{envConfig: valid}, wantCode: exitOK, wantStdout: "configuration OK"},
		{
			name: "override from environment is validated", args: []string{"--check"},
			env: map[string]string{envConfig: valid, envLogLevel: "loud"}, wantCode: exitUsage, wantStderr: `logLevel "loud"`,
		},
		{
			name: "flag beats environment", args: []string{"--check", "--log-level", "debug"},
			env: map[string]string{envConfig: valid, envLogLevel: "loud"}, wantCode: exitOK, wantStdout: "configuration OK",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			var stdout, stderr syncBuffer
			if got := run(context.Background(), tt.args, &stdout, &stderr); got != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", got, tt.wantCode, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Fatalf("stdout = %q, want %q", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Fatalf("stderr = %q, want %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

func TestRunServesUntilCancelled(t *testing.T) {
	tr := newTrust(t)
	cfg := writeConfig(t, configYAML(pinnedTL(tr.line)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr syncBuffer
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"--config", cfg, "--log-level", "debug"}, &stdout, &stderr) }()

	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(stderr.String(), "ans-authz serving") {
		if time.Now().After(deadline) {
			t.Fatalf("never started serving; stderr: %s", stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case code := <-done:
		if code != exitOK {
			t.Fatalf("exit = %d; stderr: %s", code, stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run did not return after cancellation")
	}
	if !strings.Contains(stderr.String(), "ans-authz stopped") {
		t.Fatalf("stderr lacks stop line: %s", stderr.String())
	}
}

func TestRunStartupFailures(t *testing.T) {
	tr := newTrust(t)
	failing := rootKeysServer(t, 500, "")
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	tests := []struct {
		name string
		yaml string
		args []string
		want string
	}{
		{name: "transparency log unreachable", yaml: configYAML(remoteTL(failing.URL)), want: "no root keys after"},
		{
			name: "grpc port taken", yaml: configYAML(pinnedTL(tr.line)),
			args: []string{"--grpc-listen", taken.Addr().String()}, want: "grpc listen",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr syncBuffer
			args := append([]string{"--config", writeConfig(t, tt.yaml)}, tt.args...)
			if got := run(context.Background(), args, &stdout, &stderr); got != exitRuntime {
				t.Fatalf("exit = %d, want %d; stderr: %s", got, exitRuntime, stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Fatalf("stderr = %s, want %q", stderr.String(), tt.want)
			}
		})
	}
}

func TestRunRejectsUnusableTLS(t *testing.T) {
	tr := newTrust(t)
	bogus := writeConfig(t, "not a certificate")
	yaml := strings.Replace(configYAML(pinnedTL(tr.line)), `grpc: {listen: "127.0.0.1:0"}`,
		`grpc: {listen: "127.0.0.1:0", tls: {certFile: `+bogus+`, keyFile: `+bogus+`}}`, 1)
	cfgPath := writeConfig(t, yaml)
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantMsg  string
	}{
		{name: "check", args: []string{"--config", cfgPath, "--check"}, wantCode: exitUsage, wantMsg: "load server certificate"},
		{name: "start", args: []string{"--config", cfgPath}, wantCode: exitRuntime, wantMsg: "startup failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr syncBuffer
			if got := run(context.Background(), tt.args, &stdout, &stderr); got != tt.wantCode {
				t.Fatalf("exit = %d, want %d; stderr: %s", got, tt.wantCode, stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.wantMsg) || !strings.Contains(stderr.String(), "load server certificate") {
				t.Fatalf("stderr = %s", stderr.String())
			}
		})
	}
}

func TestNewLogger(t *testing.T) {
	t.Parallel()
	tests := []struct {
		level     string
		wantDebug bool
	}{
		{level: "debug", wantDebug: true},
		{level: "info", wantDebug: false},
		{level: "nonsense", wantDebug: false},
	}
	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			t.Parallel()
			var out syncBuffer
			l := newLogger(&out, tt.level)
			if got := l.Enabled(context.Background(), slog.LevelDebug); got != tt.wantDebug {
				t.Fatalf("debug enabled = %v, want %v", got, tt.wantDebug)
			}
		})
	}
}
