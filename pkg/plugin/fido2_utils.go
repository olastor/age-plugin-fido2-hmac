package plugin

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"time"

	"github.com/olastor/go-libfido2"
)

const (
	fido2OptionClientPin        = "clientPin"
	fido2OptionRk               = "rk"
	fido2OptionMakeCredUvNotRqd = "makeCredUvNotRqd"
)

func listEligibleDevices() ([]*libfido2.Device, error) {
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return nil, err
	}

	devs := []*libfido2.Device{}
	for _, loc := range locs {
		dev, _ := libfido2.NewDevice(loc.Path)

		isFido, err := dev.IsFIDO2()
		if err != nil || !isFido {
			continue
		}

		info, err := dev.Info()
		if err != nil {
			continue
		}

		if !slices.Contains(info.Extensions, string(libfido2.HMACSecretExtension)) {
			continue
		}

		devs = append(devs, dev)
	}

	return devs, nil
}

func FindDevice(
	timeout time.Duration,
	displayMessage func(message string) error,
) (*libfido2.Device, error) {
	devicePathFromEnv := os.Getenv("FIDO2_TOKEN")
	if devicePathFromEnv != "" {
		displayMessage(fmt.Sprintf("Using device path from env: %s", devicePathFromEnv))
		return libfido2.NewDevice(devicePathFromEnv)
	}

	start := time.Now()

	for {
		if time.Since(start) >= timeout {
			break
		}

		devs, err := listEligibleDevices()
		if err != nil {
			return nil, err
		}

		if len(devs) == 1 {
			return devs[0], nil
		} else if len(devs) > 1 {
			msg := fmt.Sprintf("Found %d devices. Please touch the one you want to use.", len(devs))
			displayMessage(msg)
			return libfido2.SelectDevice(devs, 10*time.Second)
		}

		time.Sleep(200 * time.Millisecond)
	}

	return nil, errors.New("timed out waiting for device")
}

func isDeviceOptionTrue(info *libfido2.DeviceInfo, optionName string) bool {
	for _, option := range info.Options {
		if option.Name != optionName {
			continue
		}
		return option.Value == libfido2.True
	}
	return false
}

func prfSalt(salt []byte) []byte {
	// see https://www.w3.org/TR/webauthn-3/#prf-extension
	h := sha256.New()
	h.Write([]byte("WebAuthn PRF"))
	h.Write([]byte{0})
	h.Write(salt)
	return h.Sum(nil)
}

func generateNewCredential(
	device *libfido2.Device,
	pin string,
	algorithm libfido2.CredentialType,
) (credId []byte, error error) {
	cdh := libfido2.RandBytes(32)
	userId := libfido2.RandBytes(32)
	userName := b64.EncodeToString(libfido2.RandBytes(6))

	attest, err := device.MakeCredential(
		cdh,
		libfido2.RelyingParty{
			ID: DEFAULT_RELYING_PARTY,
		},
		libfido2.User{
			ID:   userId,
			Name: userName,
		},
		algorithm,
		pin,
		&libfido2.MakeCredentialOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
			RK:         libfido2.False,
		},
	)

	if err != nil {
		return nil, err
	}

	return attest.CredentialID, nil
}

func generateNewCredentialV3(
	device *libfido2.Device,
	pin string,
	algorithm libfido2.CredentialType,
	rpId string,
) (credId []byte, userId []byte, error error) {
	cdh := libfido2.RandBytes(32)
	userId = libfido2.RandBytes(32)

	// generate descriptive credential name with timestamp
	now := time.Now()
	userName := fmt.Sprintf("age-plugin-%s (%s)", PLUGIN_NAME, now.Format("06-01-02T15:04:05"))

	attest, err := device.MakeCredential(
		cdh,
		libfido2.RelyingParty{
			ID: rpId,
		},
		libfido2.User{
			ID:   userId,
			Name: userName,
		},
		algorithm,
		pin,
		&libfido2.MakeCredentialOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
			RK:         libfido2.True,
		},
	)

	if err != nil {
		return nil, nil, err
	}

	return attest.CredentialID, userId, nil
}

func listCredentials(device *libfido2.Device, rpId string, pin string) ([]*libfido2.Credential, error) {
	credentials, err := device.Credentials(rpId, pin)
	if err != nil {
		return nil, err
	}

	return credentials, nil
}

func getDiscoverableCredential(device *libfido2.Device, rpId string, userId []byte, pin string) (*libfido2.Credential, error) {
	credentials, err := listCredentials(device, rpId, pin)
	if err != nil {
		return nil, err
	}

	for _, credential := range credentials {
		if slices.Equal(credential.User.ID, userId) {
			return credential, nil
		}
	}

	return nil, errors.New("credential not found")
}

func getHmacSecret(device *libfido2.Device, rpId string, credId []byte, salt []byte, pin string) ([]byte, error) {
	if len(salt) != 32 {
		return nil, errors.New("salt must be 32 bytes")
	}

	cdh := libfido2.RandBytes(32)

	assertion, err := device.Assertion(
		rpId,
		cdh,
		[][]byte{credId},
		pin,
		&libfido2.AssertionOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
			HMACSalt:   salt,
		},
	)

	if err != nil {
		return nil, err
	}

	if assertion.HMACSecret == nil || len(assertion.HMACSecret) != 32 {
		return nil, errors.New("invalid hmac secret")
	}

	return assertion.HMACSecret, nil
}

func getHmacSecretDiscoverable(device *libfido2.Device, rpId string, userId []byte, salt []byte, pin string) ([]byte, error) {
	credential, err := getDiscoverableCredential(device, rpId, userId, pin)
	if err != nil {
		return nil, err
	}

	return getHmacSecret(device, rpId, credential.ID, salt, pin)
}

// checks if a string is a valid RP ID
// most likely passes some invalid strings,
// but for this plugin it should be good enough
// see https://www.w3.org/TR/webauthn-2/#rp-id
func validateRPID(rpID string) error {
	if rpID == "" {
		return fmt.Errorf("RP ID cannot be empty")
	}

	u, err := url.Parse("https://" + rpID)
	if err != nil {
		return fmt.Errorf("invalid RP ID: %w", err)
	}

	if u.Hostname() != rpID {
		return fmt.Errorf("invalid RP ID format")
	}

	return nil
}
