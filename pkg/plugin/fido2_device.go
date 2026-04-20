package plugin

import (
	"github.com/olastor/go-libfido2"
)

// Fido2Device abstracts FIDO2 device operations to enable mocking for testing.
// This interface defines the core operations needed.
type Fido2Device interface {
	// HasPinSet returns whether the device has a PIN configured.
	HasPinSet() (bool, error)
	// GenerateCredential creates a new FIDO2 credential with the hmac-secret extension.
	// Returns the credential ID on success.
	GenerateCredential(pin string, algorithm libfido2.CredentialType) (credId []byte, err error)
	// GetHmacSecret retrieves the HMAC secret via FIDO2 assertion using the given credential and salt.
	GetHmacSecret(credId []byte, salt []byte, pin string) ([]byte, error)
	// Info returns device information including capabilities and extensions.
	Info() (*libfido2.DeviceInfo, error)
}

// LibFido2Device wraps a *libfido2.Device to implement the Fido2Device interface.
// This is the production implementation that interacts with real hardware.
type LibFido2Device struct {
	device *libfido2.Device
}

// NewLibFido2Device creates a new LibFido2Device wrapper.
func NewLibFido2Device(device *libfido2.Device) *LibFido2Device {
	return &LibFido2Device{
		device: device,
	}
}

// HasPinSet returns whether the device has a PIN configured.
func (d *LibFido2Device) HasPinSet() (bool, error) {
	return hasPinSet(d.device)
}

// GenerateCredential creates a new FIDO2 credential with the hmac-secret extension.
func (d *LibFido2Device) GenerateCredential(pin string, algorithm libfido2.CredentialType) (credId []byte, err error) {
	return generateNewCredential(d.device, pin, algorithm)
}

// GetHmacSecret retrieves the HMAC secret via FIDO2 assertion.
func (d *LibFido2Device) GetHmacSecret(credId []byte, salt []byte, pin string) ([]byte, error) {
	return getHmacSecret(d.device, credId, salt, pin)
}

// Info returns device information.
func (d *LibFido2Device) Info() (*libfido2.DeviceInfo, error) {
	return d.device.Info()
}

// MockFido2Device is a mock implementation of Fido2Device for testing.
// It allows configuring expected responses and simulating various device behaviors.
type MockFido2Device struct {
	PinSet           bool
	HasPinSetErr     error
	GeneratedCredId  []byte
	GenerateCredErr  error
	HmacSecret       []byte
	GetHmacSecretErr error
	InfoValue        *libfido2.DeviceInfo
	InfoErr          error
}

// HasPinSet returns the configured PIN status for testing.
func (m *MockFido2Device) HasPinSet() (bool, error) {
	return m.PinSet, m.HasPinSetErr
}

// GenerateCredential returns a pre-configured credential ID for testing.
func (m *MockFido2Device) GenerateCredential(pin string, algorithm libfido2.CredentialType) (credId []byte, err error) {
	return m.GeneratedCredId, m.GenerateCredErr
}

// GetHmacSecret returns a pre-configured HMAC secret for testing.
func (m *MockFido2Device) GetHmacSecret(credId []byte, salt []byte, pin string) ([]byte, error) {
	return m.HmacSecret, m.GetHmacSecretErr
}

// Info returns pre-configured device info for testing.
func (m *MockFido2Device) Info() (*libfido2.DeviceInfo, error) {
	return m.InfoValue, m.InfoErr
}
