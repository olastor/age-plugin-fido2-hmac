package plugin

import (
	"errors"
	"github.com/keys-pub/go-libfido2"
	"time"
)

func FindDevice() (*libfido2.Device, error) {
	locs, err := libfido2.DeviceLocations()

	if err != nil {
		return nil, err
	}

	if len(locs) > 1 {
		return nil, errors.New("Too many devices")
	}

	if len(locs) == 1 {
		return libfido2.NewDevice(locs[0].Path)
	}

	return nil, nil
}

func WaitForDevice(maxWaitTimeSeconds int) (*libfido2.Device, error) {
	for i := 0; i <= maxWaitTimeSeconds; i++ {
		device, err := FindDevice()

		if err != nil {
			return nil, err
		}

		if device != nil {
			return device, nil
		}

		time.Sleep(1 * time.Second)
	}

	return nil, errors.New("Timed out waiting for device.")
}

func HasPinSet(device *libfido2.Device) (bool, error) {
	info, err := device.Info()
	if err != nil {
		return false, err
	}

	for _, option := range info.Options {
		if option.Name != "clientPin" {
			continue
		}

		return option.Value == "true", nil
	}

	return false, nil
}

func GenerateNewCredential(device *libfido2.Device, pin string, algorithm libfido2.CredentialType) (credId []byte, error error) {
	cdh := libfido2.RandBytes(32)
	userId := libfido2.RandBytes(32)
	userName := b64.EncodeToString(libfido2.RandBytes(6))

	attest, err := device.MakeCredential(
		cdh,
		libfido2.RelyingParty{
			ID: RELYING_PARTY,
		},
		libfido2.User{
			ID:   userId,
			Name: userName,
		},
		algorithm,
		pin,
		&libfido2.MakeCredentialOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
			RK:         "false",
		},
	)

	if err != nil {
		return nil, err
	}

	return attest.CredentialID, nil
}

func GetHmacSecret(device *libfido2.Device, credId []byte, salt []byte, pin string) ([]byte, error) {
	if len(salt) != 32 {
		return nil, errors.New("Salt must be 32 bytes!")
	}

	cdh := libfido2.RandBytes(32)

	assertion, err := device.Assertion(
		RELYING_PARTY,
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

	return assertion.HMACSecret, nil
}
