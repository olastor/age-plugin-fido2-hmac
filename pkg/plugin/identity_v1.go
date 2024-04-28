package plugin

import (
	"bufio"
	"errors"
	"filippo.io/age"
	"fmt"
	"github.com/keys-pub/go-libfido2"
	"github.com/olastor/age-plugin-controller/pkg/controller"
	"os"
	"sort"
	"strings"
)

func IdentityV1() error {
	var identities []*Fido2HmacIdentity
	var stanzas []*age.Stanza

	scanner := bufio.NewScanner(os.Stdin)

	err := controller.ProtocolHandler(scanner, func(command string, args []string, body []byte) (done bool, err error) {
		switch command {
		case "add-identity":
			if args[0] == MAGIC_IDENTITY || !strings.HasPrefix(args[0], strings.ToUpper(IDENTITY_HRP)) {
				// do nothing
				return false, nil
			}

			identity, err := ParseFido2HmacIdentity(args[0])
			if err != nil {
				return false, fmt.Errorf("Error parsing identity: %s", err)
			}

			identities = append(identities, identity)
		case "recipient-stanza":
			if args[1] != PLUGIN_NAME && args[1] != "X25519" {
				return false, nil
			}

			stanzas = append(stanzas, &age.Stanza{
				Type: args[1],
				Args: args[2:],
				Body: body,
			})
		}

		return false, nil
	})

	if err != nil {
		return err
	}

	if stanzas == nil {
		return fmt.Errorf("missing stanza")
	}

	for _, stanza := range stanzas {
		if stanza.Type != PLUGIN_NAME {
			continue
		}

		// plugin stanzas can be converted to an identity without the secret
		identity, err := StanzaToIdentity(stanza)
		if err != nil {
			return err
		}

		identities = append(identities, identity)
	}

	if identities == nil || len(identities) == 0 {
		return fmt.Errorf("missing identity")
	}

	device, err := FindDevice()
	if err != nil {
		return err
	}

	if device == nil {
		msg := "Please insert your token now."

		controller.SendCommand("msg", []byte(msg), true)
		device, err = WaitForDevice(120)

		if err != nil {
			return err
		}
	}

	// make sure to first try the identities without pin
	// this mixes up the indexes, so don't use them for errors
	sort.SliceStable(identities, func(i, j int) bool {
		return !identities[i].RequirePin
	})

	pin := ""
	for _, i := range identities {
		if i.Version == 1 {
			// there will be another identity with the missing salt, nonce
			// because in v1 format the info the salt is always part of the stanza
			// combine them into one identity
			if i.Salt != nil && i.CredId == nil {
				// skip the "incomplete" identity from the stanza
				continue
			}

			if i.Salt == nil {
				for _, j := range identities {
					// populate "real" identities with salt, nonce from stanza
					if j.Version != 1 || j.Salt == nil {
						continue
					}

					i.legacyNonce = j.legacyNonce
					i.Salt = j.Salt

					break
				}

				if i.Salt == nil {
					continue
				}
			}
		}

		identityPin := ""
		if pin == "" && i.RequirePin {
			msg := "Please enter your PIN:"
			pin, err = controller.RequestValue(msg, true)

			if err != nil {
				return err
			}
		}

		if i.RequirePin {
			identityPin = pin
		}

		err = i.ObtainSecretFromToken(true, identityPin)
		if err != nil {
			if errors.Is(err, libfido2.ErrNoCredentials) {
				continue
			}

			return err
		}

		key, err := i.Unwrap(stanzas)
		i.ClearSecret()
		if err != nil {
			continue
		}

		controller.SendCommand("file-key 0", []byte(key), false)
		controller.SendCommand("done", nil, true)

		return nil
	}

	return fmt.Errorf("none of the identity can decrypt the file key using this device.")
}
