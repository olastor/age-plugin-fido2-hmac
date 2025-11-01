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

type UserInterface interface {
	DisplayMessage(message string) error
	RequestValue(message string, _ bool) (s string, err error)
	Confirm(message, yes, no string) (choseYes bool, err error)
}

type TerminalUserInterface struct{}

func (u *TerminalUserInterface) DisplayMessage(message string) error {
	fmt.Fprintf(os.Stderr, "[*] %s\n", message)
	return nil
}

func (u *TerminalUserInterface) RequestValue(message string, _ bool) (s string, err error) {
	fmt.Fprintf(os.Stderr, message)
	secretBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}

	return string(secretBytes), nil
}

func (u *TerminalUserInterface) Confirm(message, yes, no string) (choseYes bool, err error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Fprintf(os.Stderr, "%s [y/n]: ", message)

	response, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}

	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(response)), "y"), nil
}

// generate new credentials interactively and return the recipient and identity strings
func NewCredentials(
	algorithm libfido2.CredentialType,
	symmetric bool,
	rpId string,
	ui UserInterface,
) (recipientString, identityString string, err error) {
	var device *libfido2.Device

	ui.DisplayMessage("Please insert your token now...")

	device, err = FindDevice(50*time.Second, ui.DisplayMessage)
	if err != nil {
		return "", "", err
	}

	deviceInfo, err := device.Info()
	if err != nil {
		return "", "", err
	}

	isPinSet := isDeviceOptionTrue(deviceInfo, fido2OptionClientPin)
	isRkSupported := isDeviceOptionTrue(deviceInfo, fido2OptionRk)

	requirePin := false
	if isPinSet {
		requirePin, err = ui.Confirm("Do you want to require a PIN for decryption?", "yes", "no")
		if err != nil {
			return "", "", err
		}
	}

	version := 1
	if !symmetric {
		version = 2

		if isRkSupported {
			discoverable, err := ui.Confirm("Do you want to use discoverable credentials (stored on the token)?", "yes", "no")
			if err != nil {
				return "", "", err
			}
			if discoverable {
				version = 3
			}
		}
	}

	var identity *Fido2HmacIdentity
	var recipient *Fido2HmacRecipient
	var x25519Recipient *age.X25519Recipient

	pin := ""
	isMakeCredUvNotRqdTrue := isDeviceOptionTrue(deviceInfo, fido2OptionMakeCredUvNotRqd)
	isPinNeededForMakeCred := !(!isPinSet || (version < 3 && isMakeCredUvNotRqdTrue))
	if requirePin || isPinNeededForMakeCred {
		pin, err = ui.RequestValue("Please enter your PIN: ", true)
		if err != nil {
			return "", "", err
		}
	}

	askSeparateIdentity := func() (bool, error) {
		return ui.Confirm(
			"Are you fine with having a separate identity (better privacy)?",
			"yes",
			"no",
		)
	}

	switch version {
	case 1:
		ui.DisplayMessage("Please touch your token...")
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

		wantsSeparateIdentity, err := askSeparateIdentity()
		if err != nil {
			return "", "", err
		}

		if wantsSeparateIdentity {
			return recipient.String(), identity.String(), nil
		}

		return recipient.String(), "", nil
	case 2:
		ui.DisplayMessage("Please touch your token...")
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
			RpId:       DEFAULT_RELYING_PARTY,
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

		wantsSeparateIdentity, err := askSeparateIdentity()
		if err != nil {
			return "", "", err
		}

		if wantsSeparateIdentity {
			return x25519Recipient.String(), identity.String(), nil
		}

		return recipient.String(), "", nil
	case 3:
		ui.DisplayMessage("Please touch your token...")
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
}

func ListCredentials(
	rpId string,
	ui UserInterface,
) error {
	ui.DisplayMessage("Please insert your token now...")

	device, err := FindDevice(50*time.Second, ui.DisplayMessage)
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
			Version: 3,
			// TODO: fix for credentials without pin set
			RequirePin: true,
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
