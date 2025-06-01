package plugin

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/ldclabs/cose/key"
	"github.com/savely-krasovsky/go-ctaphid/pkg/ctaptypes"
	"github.com/savely-krasovsky/go-ctaphid/pkg/device"
	"github.com/savely-krasovsky/go-ctaphid/pkg/sugar"
)

func FindDevice(
	timeout time.Duration,
	displayMessage func(message string) error,
) (*device.Device, error) {
	devicePathFromEnv := os.Getenv("FIDO2_TOKEN")
	if devicePathFromEnv != "" {
		displayMessage(fmt.Sprintf("Using device path from env: %s", devicePathFromEnv))
		return device.New(devicePathFromEnv)
	}

	start := time.Now()

	for {
		if time.Since(start) >= timeout {
			break
		}

		devs, err := sugar.EnumerateFIDODevices()
		if err != nil {
			return nil, err
		}

		if len(devs) == 1 {
			return sugar.SelectDevice(sugar.WithDeviceInfos(devs))
		} else if len(devs) > 1 {
			msg := fmt.Sprintf("Found %d devices. Please touch the one you want to use.", len(devs))
			displayMessage(msg)
			return sugar.SelectDevice(sugar.WithDeviceInfos(devs))
		}

		time.Sleep(200 * time.Millisecond)
	}

	return nil, errors.New("Timed out waiting for device.")
}

func HasPinSet(device *device.Device) (bool, error) {
	info := device.GetInfo()
	for k, v := range info.Options {
		if k != ctaptypes.OptionClientPIN {
			continue
		}

		return v == true, nil
	}

	return false, nil
}

func randBytes(length int) []byte {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

func generateNewCredential(
	device *device.Device,
	pin string,
	algorithm key.Alg,
) (credId []byte, error error) {
	cdh := randBytes(32)
	userId := randBytes(32)
	userName := b64.EncodeToString(randBytes(6))

	token, err := device.GetPinUvAuthTokenUsingPIN(
		pin,
		ctaptypes.PermissionMakeCredential,
		RELYING_PARTY,
	)
	if err != nil {
		return nil, err
	}

	attest, err := device.MakeCredential(
		token,
		cdh,
		ctaptypes.PublicKeyCredentialRpEntity{
			ID: RELYING_PARTY,
		},
		ctaptypes.PublicKeyCredentialUserEntity{
			ID:   userId,
			Name: userName,
		},
		[]ctaptypes.PublicKeyCredentialParameters{{
			Type:      ctaptypes.PublicKeyCredentialTypePublicKey,
			Algorithm: algorithm,
		}},
		nil,
		map[ctaptypes.ExtensionIdentifier]any{
			ctaptypes.ExtensionIdentifierHMACSecret: true,
		},
		map[ctaptypes.Option]bool{
			ctaptypes.OptionResidentKeys: false,
		},
		0,
		nil,
	)
	if err != nil {
		return nil, err
	}

	return attest.AuthData.AttestedCredentialData.CredentialID, nil
}

var ErrNoCredentials = errors.New("no credentials found")

func getHmacSecret(dev *device.Device, credId []byte, salt []byte, pin string) ([]byte, error) {
	if len(salt) != 32 {
		return nil, errors.New("Salt must be 32 bytes!")
	}

	cdh := randBytes(32)

	token, err := dev.GetPinUvAuthTokenUsingPIN(
		pin,
		ctaptypes.PermissionGetAssertion,
		RELYING_PARTY,
	)
	if err != nil {
		return nil, err
	}

	for assertion, err := range dev.GetAssertion(
		token,
		RELYING_PARTY,
		cdh,
		[]ctaptypes.PublicKeyCredentialDescriptor{
			{
				Type: ctaptypes.PublicKeyCredentialTypePublicKey,
				ID:   credId,
			},
		},
		map[ctaptypes.ExtensionIdentifier]any{
			ctaptypes.ExtensionIdentifierHMACSecret: &device.HMACSecretInput{
				Salt1: salt,
			},
		},
		nil,
	) {
		if err != nil {
			return nil, err
		}

		secret, ok := assertion.AuthData.Extensions[ctaptypes.ExtensionIdentifierHMACSecret]
		if !ok {
			return nil, errors.New("invalid hmac secret")
		}

		secretBytes, ok := secret.(*device.HMACSecretOutput)
		if !ok {
			return nil, errors.New("invalid hmac secret")
		}

		return secretBytes.Output1, nil
	}

	return nil, ErrNoCredentials
}
