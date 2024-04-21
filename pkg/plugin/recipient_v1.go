package plugin

import (
	"bufio"
	"fmt"
	"github.com/olastor/age-plugin-sss/pkg/sss"
	"os"
)

func RecipientV1() error {
	var recipient *Fido2HmacRecipient
	var identity *Fido2HmacIdentity
	var fileKey []byte

	scanner := bufio.NewScanner(os.Stdin)

	err := sss.ProtocolHandler(scanner, func(command string, args []string, body []byte) (done bool, err error) {
		switch command {
		case "add-recipient":
			if recipient != nil || identity != nil {
				return false, fmt.Errorf("can only encrypt to one recipient or identity")
			}

			recipient, err = ParseFido2HmacRecipient(args[0])
			if err != nil {
				return false, err
			}
		case "add-identity":
			if recipient != nil || identity != nil {
				return false, fmt.Errorf("can only encrypt to one recipient or identity")
			}

			identity, err = ParseFido2HmacIdentity(args[0])
			if err != nil {
				return false, err
			}
		case "wrap-file-key":
			fileKey = body
		}

		return false, nil
	})

	if err != nil {
		return err
	}

	if recipient != nil {
		stanzas, err := recipient.Wrap(fileKey)
		if err != nil {
			return err
		}

		sss.SendCommand(StanzaArgsLine(stanzas[0]), stanzas[0].Body, true)
		sss.SendCommand("done", nil, true)

		return nil
	}

	if identity != nil {
		stanzas, err := identity.Wrap(fileKey)
		identity.ClearSecret()
		if err != nil {
			return err
		}

		sss.SendCommand(StanzaArgsLine(stanzas[0]), stanzas[0].Body, true)
		sss.SendCommand("done", nil, true)

		return nil
	}

	return fmt.Errorf("failed to wrap")
}
