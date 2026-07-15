package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/olastor/age-plugin-fido2-hmac/pkg/plugin"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: age-plugin-fido2-hmac-session -- COMMAND [ARGS...]")
		os.Exit(2)
	}

	baseDir := os.Getenv("XDG_RUNTIME_DIR")
	if baseDir == "" {
		baseDir = os.TempDir()
	}
	sessionDir, err := os.MkdirTemp(baseDir, "age-plugin-fido2-hmac-session-")
	if err != nil {
		fatal(err)
	}
	defer os.RemoveAll(sessionDir)
	if err := os.Chmod(sessionDir, 0o700); err != nil {
		fatal(err)
	}

	capability := make([]byte, 32)
	if _, err := rand.Read(capability); err != nil {
		fatal(fmt.Errorf("generate session capability: %w", err))
	}

	cache := plugin.NewSessionCache()
	defer cache.Close()

	server, err := plugin.NewSessionServer(filepath.Join(sessionDir, "session.sock"), capability, cache)
	if err != nil {
		fatal(err)
	}
	defer server.Close()

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve() }()

	command := exec.Command(args[0], args[1:]...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.Env = sessionEnvironment(os.Environ(), server, capability)

	if err := command.Start(); err != nil {
		fatal(fmt.Errorf("start command: %w", err))
	}

	signalCh := make(chan os.Signal, 8)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signalCh)
	go func() {
		for sig := range signalCh {
			if command.Process != nil {
				_ = command.Process.Signal(sig)
			}
		}
	}()

	waitErr := command.Wait()
	_ = server.Close()
	select {
	case err := <-serverErr:
		if err != nil {
			fmt.Fprintf(os.Stderr, "session broker: %s\n", err)
		}
	default:
	}

	if waitErr == nil {
		return
	}
	if exitErr, ok := waitErr.(*exec.ExitError); ok {
		if code := exitErr.ProcessState.ExitCode(); code >= 0 {
			os.Exit(code)
		}
	}
	fatal(waitErr)
}

func sessionEnvironment(environment []string, server *plugin.SessionServer, capability []byte) []string {
	// The wrapper only exports session credentials to its child command. Remove
	// inherited values first so nested invocations cannot accidentally attach to
	// an unrelated parent session.
	filtered := make([]string, 0, len(environment)+2)
	for _, entry := range environment {
		if len(entry) > len(plugin.SessionSocketEnv) && entry[:len(plugin.SessionSocketEnv)] == plugin.SessionSocketEnv && entry[len(plugin.SessionSocketEnv)] == '=' {
			continue
		}
		if len(entry) > len(plugin.SessionCapabilityEnv) && entry[:len(plugin.SessionCapabilityEnv)] == plugin.SessionCapabilityEnv && entry[len(plugin.SessionCapabilityEnv)] == '=' {
			continue
		}
		filtered = append(filtered, entry)
	}
	filtered = append(filtered,
		plugin.SessionSocketEnv+"="+serverSocket(server),
		plugin.SessionCapabilityEnv+"="+plugin.SessionCapabilityString(capability),
	)
	return filtered
}

func serverSocket(server *plugin.SessionServer) string {
	return server.SocketPath()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
