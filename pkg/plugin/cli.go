package plugin

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/olastor/go-libfido2"
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
	algorithm libfido2.CredentialType,
	symmetric bool,
	rpId string,
	displayMessage func(message string) error,
	requestValue func(prompt string, secret bool) (string, error),
	confirm func(prompt, yes, no string) (choseYes bool, err error),
) (string, string, error) {
	var device *libfido2.Device

	displayMessage("Please insert your token now...")

	device, err := FindDevice(50*time.Second, displayMessage)
	if err != nil {
		return "", "", err
	}

	hasPinSet, err := HasPinSet(device)
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

	version := 1
	if !symmetric {
		version = 2
		discoverable, err := confirm("Do you want to use discoverable credentials (stored on the token)?", "yes", "no")
		if err != nil {
			return "", "", err
		}
		if discoverable {
			version = 3
		}
	}

	var identity *Fido2HmacIdentity
	var recipient *Fido2HmacRecipient
	var x25519Recipient *age.X25519Recipient

	switch version {
	case 1:
		displayMessage("Please touch your token...")
		credId, err := generateNewCredential(device, pin, algorithm)
		if err != nil {
			return "", "", err
		}

		identity = &Fido2HmacIdentity{
			Version:    1,
			RequirePin: requirePin,
			Salt:       nil,
			CredId:     credId,
			Device:     device,
		}
		recipient, err = identity.Recipient()
		if err != nil {
			return "", "", err
		}
	case 2:
		displayMessage("Please touch your token...")
		credId, err := generateNewCredential(device, pin, algorithm)
		if err != nil {
			return "", "", err
		}

		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return "", "", err
		}

		identity = &Fido2HmacIdentity{
			Version:    2,
			RequirePin: requirePin,
			Salt:       salt,
			CredId:     credId,
			Device:     device,
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
	case 3:
		displayMessage("Please touch your token...")
		credId, userId, err := generateNewCredentialV3(device, pin, algorithm, rpId)
		if err != nil {
			return "", "", err
		}

		identity = &Fido2HmacIdentity{
			Version:    3,
			RequirePin: requirePin,
			UserId:     userId,
			RpId:       rpId,
			CredId:     credId,
			Device:     device,
		}

		_, err = identity.obtainSecretFromToken(pin)
		if err != nil {
			return "", "", err
		}

		x25519Identity, err := identity.X25519Identity()
		if err != nil {
			return "", "", err
		}
		identity.ClearSecret()
		x25519Recipient = x25519Identity.Recipient()

		return x25519Recipient.String(), identity.String(), nil
	default:
		return "", "", fmt.Errorf("unsupported version: %d", version)
	}

	wantsSeparateIdentity, err := confirm(
		"Are you fine with having a separate identity (better privacy)?",
		"yes",
		"no",
	)
	if err != nil {
		return "", "", err
	}

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
	algorithm libfido2.CredentialType,
	symmetric bool,
	rpId string,
) (string, string, error) {
	displayMessage := func(message string) error {
		fmt.Fprintf(os.Stderr, "[*] %s\n", message)
		return nil
	}
	requestValue := func(message string, _ bool) (s string, err error) {
		fmt.Fprintf(os.Stderr, message)
		secretBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", err
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
		rpId,
		displayMessage,
		requestValue,
		confirm,
	)
}

func ListCredentialsCli(rpId string) error {
	displayMessage := func(message string) error {
		fmt.Fprintf(os.Stderr, "[*] %s\n", message)
		return nil
	}

	displayMessage("Please insert your token now...")

	device, err := FindDevice(50*time.Second, displayMessage)
	if err != nil {
		return err
	}

	hasPinSet, err := HasPinSet(device)
	if err != nil {
		return err
	}

	pin := ""
	if hasPinSet {
		fmt.Fprintf(os.Stderr, "[*] Please enter your PIN: ")
		pinBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintf(os.Stderr, "\n")
		if err != nil {
			return err
		}
		pin = string(pinBytes)
	}

	credentials, err := listCredentials(device, rpId, pin)
	if err != nil {
		return err
	}

	if len(credentials) == 0 {
		fmt.Fprintf(os.Stdout, "No credentials found for %s\n", rpId)
		return nil
	}

	fmt.Fprintf(os.Stdout, "Credentials for %s:\n\n", rpId)
	for i, cred := range credentials {
		if !strings.HasPrefix(cred.User.Name, fmt.Sprintf("age-plugin-%s", PLUGIN_NAME)) {
			continue
		}

		fmt.Fprintf(os.Stdout, "Credential %d:\n", i+1)
		fmt.Fprintf(os.Stdout, "  Name:    %s\n", cred.User.Name)

		identity := &Fido2HmacIdentity{
			Version:    3,
			RequirePin: false,
			UserId:     cred.User.ID,
			RpId:       rpId,
			CredId:     cred.ID,
			Device:     device,
		}
		_, err = identity.obtainSecretFromToken(pin)
		if err != nil {
			return err
		}
		x25519Identity, err := identity.X25519Identity()
		if err != nil {
			return err
		}
		x25519Recipient := x25519Identity.Recipient()
		identity.ClearSecret()
		identityString := identity.String()
		recipientString := x25519Recipient.String()

		fmt.Fprintf(os.Stdout, "  Recipient:\t%s\n", recipientString)
		fmt.Fprintf(os.Stdout, "  Identity:\t%s\n", identityString)
		fmt.Fprintf(os.Stdout, "\n")
	}

	return nil
}
