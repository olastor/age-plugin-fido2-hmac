package plugin

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/ldclabs/cose/key"
	"github.com/savely-krasovsky/go-ctaphid/pkg/device"
	"golang.org/x/term"
)

func promptYesNo(s string) (bool, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Fprintf(os.Stderr, "%s [y/n]: ", s)

	response, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}

	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(response)), "y"), nil
}

func NewCredentials(
	algorithm key.Alg,
	symmetric bool,
	displayMessage func(message string) error,
	requestValue func(prompt string, secret bool) (string, error),
	confirm func(prompt, yes, no string) (choseYes bool, err error),
) (string, string, error) {
	var dev *device.Device

	displayMessage("Please insert your token now...")

	dev, err := FindDevice(50*time.Second, displayMessage)
	if err != nil {
		return "", "", err
	}

	hasPinSet, err := HasPinSet(dev)
	if err != nil {
		return "", "", err
	}

	pin := ""
	if hasPinSet {
		pin, err = requestValue("Please enter your PIN: ", true)
		if err != nil {
			return "", "", err
		}
	}

	displayMessage("Please touch your token...")
	credId, err := generateNewCredential(dev, pin, algorithm)
	if err != nil {
		return "", "", err
	}

	requirePin := false
	if hasPinSet {
		requirePin, err = confirm("Do you want to require a PIN for decryption?", "yes", "no")
		if err != nil {
			return "", "", err
		}
	}

	if !requirePin {
		pin = ""
	}

	var identity *Fido2HmacIdentity
	var recipient *Fido2HmacRecipient
	var x25519Recipient *age.X25519Recipient

	if symmetric {
		identity = &Fido2HmacIdentity{
			Version:    1,
			RequirePin: requirePin,
			Salt:       nil,
			CredId:     credId,
			Device:     dev,
		}
		recipient, err = identity.Recipient()
		if err != nil {
			return "", "", err
		}
	} else {
		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return "", "", err
		}

		identity = &Fido2HmacIdentity{
			Version:    2,
			RequirePin: requirePin,
			Salt:       salt,
			CredId:     credId,
			Device:     dev,
		}

		_, err = identity.obtainSecretFromToken(pin)
		if err != nil {
			return "", "", err
		}

		recipient, err = identity.Recipient()
		identity.ClearSecret()
		if err != nil {
			return "", "", err
		}

		x25519Recipient, err = recipient.X25519Recipient()
		if err != nil {
			return "", "", err
		}
	}

	wantsSeparateIdentity, err := confirm(
		"Are you fine with having a separate identity (better privacy)?",
		"yes",
		"no",
	)

	if wantsSeparateIdentity {
		if recipient.Version == 1 {
			return recipient.String(), identity.String(), nil
		} else {
			return x25519Recipient.String(), identity.String(), nil
		}
	} else {
		return recipient.String(), "", nil
	}
}

func NewCredentialsCli(
	algorithm key.Alg,
	symmetric bool,
) (string, string, error) {
	displayMessage := func(message string) error {
		fmt.Fprintf(os.Stderr, "[*] %s\n", message)
		return nil
	}
	requestValue := func(message string, _ bool) (s string, err error) {
		fmt.Fprintf(os.Stderr, message)

		var secretBytes []byte

		fd := int(os.Stdin.Fd())
		if term.IsTerminal(fd) {
			secretBytes, err = term.ReadPassword(fd)
			if err != nil {
				return "", err
			}
		} else {
			reader := bufio.NewReader(os.Stdin)
			pin, err := reader.ReadString('\n')
			if err != nil {
				return "", err
			}
			secretBytes = []byte(strings.TrimSpace(pin))
		}

		return string(secretBytes), nil
	}
	confirm := func(message, yes, no string) (choseYes bool, err error) {
		answerYes, err := promptYesNo(fmt.Sprintf("[*] %s", message))
		if err != nil {
			return false, err
		}

		return answerYes, nil
	}

	return NewCredentials(
		algorithm,
		symmetric,
		displayMessage,
		requestValue,
		confirm,
	)
}
