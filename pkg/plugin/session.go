package plugin

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"filippo.io/age"
	page "filippo.io/age/plugin"
)

const (
	SessionSocketEnv     = "AGE_PLUGIN_FIDO2_HMAC_SESSION_SOCKET"
	SessionCapabilityEnv = "AGE_PLUGIN_FIDO2_HMAC_SESSION_CAPABILITY"
	sessionHandshakeText = "age-plugin-fido2-hmac-session-v1\x00"
)

// SessionServer serves ordinary age identity-v1 plugin connections while
// sharing a cache between them. The server itself never exposes the derived
// identity to a client; each connection still receives only the file key that
// the age protocol requires.
type SessionServer struct {
	listener   net.Listener
	socketPath string
	capability []byte
	cache      *SessionCache
	wg         sync.WaitGroup
	closeOnce  sync.Once
}

// NewSessionServer creates a server on socketPath. The socket is restricted to
// the current user and the capability is required in addition to filesystem
// permissions so an accidentally reused path cannot attach to a session.
func NewSessionServer(socketPath string, capability []byte, cache *SessionCache) (*SessionServer, error) {
	if socketPath == "" {
		return nil, errors.New("session socket path is empty")
	}
	if len(capability) == 0 {
		return nil, errors.New("session capability is empty")
	}
	if cache == nil {
		cache = NewSessionCache()
	}

	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return nil, fmt.Errorf("create session directory: %w", err)
	}
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("session socket path exists and is not a socket: %s", socketPath)
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, fmt.Errorf("remove stale session socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect session socket path: %w", err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen on session socket: %w", err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(socketPath)
		return nil, fmt.Errorf("protect session socket: %w", err)
	}

	capabilityCopy := append([]byte(nil), capability...)
	return &SessionServer{
		listener:   listener,
		socketPath: socketPath,
		capability: capabilityCopy,
		cache:      cache,
	}, nil
}

// SocketPath returns the private socket used by this session.
func (s *SessionServer) SocketPath() string {
	if s == nil {
		return ""
	}
	return s.socketPath
}

// Serve accepts proxy connections until Close is called.
func (s *SessionServer) Serve() error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			_ = s.serveConnection(conn)
		}()
	}
}

// Close stops accepting connections, waits for active protocol handlers, and
// clears all cached derived secrets.
func (s *SessionServer) Close() error {
	if s == nil {
		return nil
	}

	var err error
	s.closeOnce.Do(func() {
		err = s.listener.Close()
		s.wg.Wait()
		s.cache.Close()
		// Keep the path separately: after Close, a net.UnixListener's Addr is
		// implementation-dependent and may no longer be safe to inspect.
		_ = os.Remove(s.socketPath)
		for i := range s.capability {
			s.capability[i] = 0
		}
	})
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (s *SessionServer) serveConnection(conn net.Conn) error {
	defer conn.Close()

	if err := authenticateSession(conn, s.capability); err != nil {
		return err
	}

	p, err := page.New(PLUGIN_NAME)
	if err != nil {
		return err
	}
	p.SetIO(conn, conn, os.Stderr)
	p.HandleIdentityEncoding(func(identity string) (age.Identity, error) {
		return s.identityForSession(identity, p)
	})

	if exitCode := p.IdentityV1(); exitCode != 0 {
		return fmt.Errorf("identity-v1 handler exited with status %d", exitCode)
	}
	return nil
}

func (s *SessionServer) identityForSession(identity string, p *page.Plugin) (*Fido2HmacIdentity, error) {
	i, err := ParseFido2HmacIdentity(identity)
	if err != nil {
		return nil, err
	}

	i.sessionCache = s.cache
	i.sessionIdentity = identity
	i.Plugin = p

	// Attach the cached secret immediately. Besides avoiding a second token
	// lookup, this keeps every unwrap path independent of a live device after
	// the first authorization.
	if secret, ok := s.cache.Get(identity); ok {
		i.secretKey = secret
		return i, nil
	}

	i.Device, err = FindDevice(50*time.Second, p.DisplayMessage)
	if err != nil {
		return nil, err
	}
	return i, nil
}

func authenticateSession(conn net.Conn, expected []byte) error {
	magic := make([]byte, len(sessionHandshakeText))
	if _, err := io.ReadFull(conn, magic); err != nil {
		return fmt.Errorf("read session handshake: %w", err)
	}
	if string(magic) != sessionHandshakeText {
		return errors.New("invalid session handshake")
	}

	capability := make([]byte, len(expected))
	if _, err := io.ReadFull(conn, capability); err != nil {
		return fmt.Errorf("read session capability: %w", err)
	}
	if subtle.ConstantTimeCompare(capability, expected) != 1 {
		return errors.New("invalid session capability")
	}
	for i := range capability {
		capability[i] = 0
	}
	return nil
}

// ProxySession turns one ordinary age plugin process into a connection to a
// command-scoped session server. It returns only after both sides close.
func ProxySession(socketPath string, capability []byte) error {
	if socketPath == "" || len(capability) == 0 {
		return errors.New("session environment is incomplete")
	}
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("connect to session broker: %w", err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, sessionHandshakeText); err != nil {
		return fmt.Errorf("write session handshake: %w", err)
	}
	if _, err := conn.Write(capability); err != nil {
		return fmt.Errorf("write session capability: %w", err)
	}

	copyDone := make(chan error, 2)
	go func() {
		_, copyErr := io.Copy(conn, os.Stdin)
		if unixConn, ok := conn.(*net.UnixConn); ok {
			_ = unixConn.CloseWrite()
		}
		copyDone <- copyErr
	}()
	go func() {
		_, copyErr := io.Copy(os.Stdout, conn)
		copyDone <- copyErr
	}()

	first := <-copyDone
	second := <-copyDone
	if first != nil && !errors.Is(first, net.ErrClosed) {
		return first
	}
	if second != nil && !errors.Is(second, net.ErrClosed) {
		return second
	}
	return nil
}

// SessionCapabilityString is used by the command wrapper when constructing
// the child environment. Keeping the encoding here avoids accidental shell
// quoting or binary environment values.
func SessionCapabilityString(capability []byte) string {
	return hex.EncodeToString(capability)
}

// ParseSessionCapability decodes the environment representation.
func ParseSessionCapability(value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("session capability is empty")
	}
	capability, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode session capability: %w", err)
	}
	return capability, nil
}
