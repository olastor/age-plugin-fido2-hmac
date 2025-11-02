package plugin

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/olastor/go-libfido2"
	"golang.org/x/term"
)

type UserInterface interface {
	DisplayMessage(message string) error
	DisplayResult(message string) error
	RequestValue(message string, secret bool) (s string, err error)
	Confirm(message, yes, no string) (choseYes bool, err error)
}

type TerminalUserInterface struct{}

func (u *TerminalUserInterface) DisplayMessage(message string) error {
	fmt.Fprintf(os.Stderr, "[*] %s\n", message)
	return nil
}

func (u *TerminalUserInterface) DisplayResult(message string) error {
	fmt.Fprintf(os.Stdout, "%s\n", message)
	return nil
}

func (u *TerminalUserInterface) RequestValue(message string, secret bool) (s string, err error) {
	fmt.Fprintf(os.Stderr, "%s", message)
	if secret {
		secretBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(os.Stderr, "\n")

		return string(secretBytes), nil
	}

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(input), nil
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
			RpId:       DEFAULT_RELYING_PARTY,
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
	exportSecretKey bool,
	ui UserInterface,
) error {
	ui.DisplayMessage("Please insert your token now...")

	device, err := FindDevice(50*time.Second, ui.DisplayMessage)
	if err != nil {
		return err
	}

	deviceInfo, err := device.Info()
	if err != nil {
		return err
	}

	hasPinSet := isDeviceOptionTrue(deviceInfo, fido2OptionClientPin)
	if !hasPinSet {
		return fmt.Errorf("no PIN set on the token, cannot list credentials")
	}

	pin, err := ui.RequestValue("Please enter your PIN: ", true)
	if err != nil {
		return err
	}

	credentials, err := listCredentials(device, rpId, pin)
	if err != nil {
		return err
	}

	if len(credentials) == 0 {
		ui.DisplayMessage(fmt.Sprintf("No credentials found for %s", rpId))
		return nil
	}

	listMessage := fmt.Sprintf("Credentials for %s:\n", rpId)
	for i, cred := range credentials {
		if !strings.HasPrefix(cred.User.Name, fmt.Sprintf("age-plugin-%s", PLUGIN_NAME)) {
			continue
		}

		listMessage += fmt.Sprintf("\t%d: %s\n", i, cred.User.Name)
	}
	ui.DisplayMessage(listMessage)

	selectedIndexString, err := ui.RequestValue("Please enter the index of the credential you want to use: ", false)
	if err != nil {
		return err
	}

	selectedIndex, err := strconv.Atoi(selectedIndexString)
	if err != nil {
		return err
	}

	if selectedIndex < 0 || selectedIndex >= len(credentials) {
		return fmt.Errorf("selected index is out of range")
	}

	cred := credentials[selectedIndex]

	requirePin, err := ui.Confirm("Do you want to require a PIN for decryption?", "yes", "no")
	if err != nil {
		return err
	}

	identity := &Fido2HmacIdentity{
		Version:    3,
		RequirePin: requirePin,
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

	if exportSecretKey {
		identityString = x25519Identity.String()
	}

	ui.DisplayResult(fmt.Sprintf("# public key: %s\n%s\n", recipientString, identityString))
	return nil
}
