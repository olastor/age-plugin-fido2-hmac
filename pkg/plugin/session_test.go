package plugin

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIdentityForSessionAttachesCachedSecret(t *testing.T) {
	cache := NewSessionCache()
	defer cache.Close()

	encoded := (&Fido2HmacIdentity{
		Version: 2,
		Salt:    make([]byte, 32),
		CredId:  make([]byte, 50),
	}).String()
	want := bytes.Repeat([]byte{0x42}, 32)
	if _, err := cache.Load(encoded, func() ([]byte, error) { return want, nil }); err != nil {
		t.Fatalf("Load: %v", err)
	}

	server := &SessionServer{cache: cache}
	identity, err := server.identityForSession(encoded, nil)
	if err != nil {
		t.Fatalf("identityForSession: %v", err)
	}
	if !bytes.Equal(identity.secretKey, want) {
		t.Fatal("identity did not receive the cached secret")
	}
	if err := identity.LoadSecret(""); err != nil {
		t.Fatalf("cached identity tried to use a device: %v", err)
	}
}

func TestNewSessionServerRejectsNonSocketPath(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "session.sock")
	if err := os.WriteFile(socketPath, []byte("keep me"), 0o600); err != nil {
		t.Fatalf("create sentinel: %v", err)
	}

	_, err := NewSessionServer(socketPath, []byte("capability"), NewSessionCache())
	if err == nil {
		t.Fatal("NewSessionServer accepted a regular file as its socket path")
	}
	if !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("unexpected error: %v", err)
	}
	contents, readErr := os.ReadFile(socketPath)
	if readErr != nil {
		t.Fatalf("sentinel was removed: %v", readErr)
	}
	if string(contents) != "keep me" {
		t.Fatalf("sentinel changed: %q", contents)
	}
}

func TestSessionServerCloseRemovesSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "session.sock")
	server, err := NewSessionServer(socketPath, []byte("capability"), NewSessionCache())
	if err != nil {
		t.Fatalf("NewSessionServer: %v", err)
	}

	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve() }()
	if err := server.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("Serve after Close: %v", err)
	}
	if _, err := os.Stat(socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket path still exists: %v", err)
	}
}
