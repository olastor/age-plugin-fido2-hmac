package plugin

import (
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	page "filippo.io/age/plugin"
	"github.com/olastor/go-libfido2"
)

// Generates a new credential and returns recipient(s) and identity
// based on the user's responses (each may be nil). If `askForIdentity`
// is false, it's assumed that no identity shall be generated.
func NewCredentials(
	algorithm libfido2.CredentialType,
	symmetric bool,
	ui *page.ClientUI,
	askForIdentity bool,
) (*age.X25519Recipient, *Fido2HmacRecipient, *Fido2HmacIdentity, error) {
	var device *libfido2.Device

	displayMessage := func(message string) error {
		return ui.DisplayMessage(PLUGIN_NAME, message)
	}

	err := displayMessage("Please insert your token now...\n")
	if err != nil {
		return nil, nil, nil, err
	}

	device, err = FindDevice(50*time.Second, displayMessage)
	if err != nil {
		return nil, nil, nil, err
	}

	hasPinSet, err := HasPinSet(device)
	if err != nil {
		return nil, nil, nil, err
	}

	pin := ""
	if hasPinSet {
		pin, err = ui.RequestValue(PLUGIN_NAME, "Please enter your PIN:", true)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	err = displayMessage("Please touch your token...\n")
	if err != nil {
		return nil, nil, nil, err
	}
	credId, err := generateNewCredential(device, pin, algorithm)
	if err != nil {
		return nil, nil, nil, err
	}

	requirePin := false
	if hasPinSet {
		requirePin, err = ui.Confirm(PLUGIN_NAME, "Do you want to require a PIN for decryption?", "yes", "no")
		if err != nil {
			return nil, nil, nil, err
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
			Device:     device,
			UI:         ui,
		}
		recipient, err = identity.Recipient()
		if err != nil {
			return nil, nil, nil, err
		}
	} else {
		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, nil, err
		}

		identity = &Fido2HmacIdentity{
			Version:    2,
			RequirePin: requirePin,
			Salt:       salt,
			CredId:     credId,
			Device:     device,
			UI:         ui,
		}

		_, err = identity.obtainSecretFromToken(pin)
		if err != nil {
			return nil, nil, nil, err
		}

		recipient, err = identity.Recipient()
		identity.ClearSecret()
		if err != nil {
			return nil, nil, nil, err
		}

		x25519Recipient, err = recipient.X25519Recipient()
		if err != nil {
			return nil, nil, nil, err
		}
	}

	wantsSeparateIdentity := false
	if askForIdentity {
		wantsSeparateIdentity, err = ui.Confirm(
			PLUGIN_NAME,
			"Are you fine with having a separate identity (better privacy)?\n",
			"yes",
			"no",
		)

		if err != nil {
			return nil, nil, nil, err
		}
	}

	if wantsSeparateIdentity {
		if recipient.Version == 1 {
			return nil, recipient, identity, nil
		} else {
			return x25519Recipient, nil, identity, nil
		}
	} else {
		return nil, recipient, nil, nil
	}
}

const defaultPrintfPrefix = "%s plugin: "

func NewCredentialsCli(
	algorithm libfido2.CredentialType,
	symmetric bool,
) (*age.X25519Recipient, *Fido2HmacRecipient, *Fido2HmacIdentity, error) {
	printf := func(format string, v ...any) {
		if strings.HasPrefix(format, defaultPrintfPrefix) {
			// try to use a nicer prefix if possible
			newFormat := strings.Replace(format, defaultPrintfPrefix, "[*] ", 1)
			fmt.Fprintf(os.Stderr, newFormat, v[1:]...)
			return
		}

		fmt.Fprintf(os.Stderr, format, v...)
	}
	warningf := func(format string, v ...any) {
		fmt.Fprintf(os.Stderr, format, v...)
	}
	ui := page.NewTerminalUI(printf, warningf)

	return NewCredentials(
		algorithm,
		symmetric,
		ui,
		true,
	)
}
