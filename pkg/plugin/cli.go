package plugin

import (
	"bufio"
	"crypto/rand"
	"filippo.io/age"
	"fmt"
	"github.com/keys-pub/go-libfido2"
	"golang.org/x/term"
	"os"
	"strings"
	"time"
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

func GenerateNewCli(algorithm libfido2.CredentialType, symmetric bool) {
	device, err := FindDevice()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "[*] Please insert your token now...\n")

	if device == nil {
		device, err = WaitForDevice(120)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}
	}

	hasPinSet, err := HasPinSet(device)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}

	pin := ""
	if hasPinSet {
		fmt.Fprintf(os.Stderr, "Please enter your PIN: ")
		pinBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		pin = string(pinBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}
	}

	fmt.Fprintf(os.Stderr, "\n[*] Please touch your token...\n")
	credId, err := GenerateNewCredential(device, pin, algorithm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}

	requirePin := false
	if hasPinSet {
		requirePin, err = promptYesNo("[*] Do you want to require a PIN for decryption?")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
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
		}
		recipient, err = identity.Recipient()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}
	} else {
		identity = &Fido2HmacIdentity{
			Version:    2,
			RequirePin: requirePin,
			Salt:       salt,
			CredId:     credId,
		}

		err = identity.ObtainSecretFromToken(false, pin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}

		recipient, err = identity.Recipient()
		identity.ClearSecret()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}

		x25519Recipient, err = recipient.X25519Recipient()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}
	}

	wantsSeparateIdentity, err := promptYesNo("[*] Are you fine with having a separate identity (better privacy)?")

	fmt.Fprintf(os.Stdout, "# created: %s\n", time.Now().Format(time.RFC3339))
	if wantsSeparateIdentity {
		if recipient.Version == 1 {
			fmt.Fprintf(os.Stdout, "# public key: %s\n%s\n", recipient, identity)
		} else {
			fmt.Fprintf(os.Stdout, "# public key: %s\n%s\n", x25519Recipient, identity)
		}
	} else {
		fmt.Fprintf(os.Stdout, "# public key: %s\n", recipient)
		fmt.Fprintf(os.Stdout, "# for decryption, use `age-plugin-fido2-hmac -m` to get the following static magic identity.\n")
		fmt.Fprintf(os.Stdout, "%s\n", MAGIC_IDENTITY)
	}
}
