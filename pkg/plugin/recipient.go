package plugin

import (
	"encoding/binary"
	"fmt"
	"slices"

	"filippo.io/age"
	"github.com/olastor/age-plugin-fido2-hmac/internal/bech32"
)

func (r *Fido2HmacRecipient) X25519Recipient() (*age.X25519Recipient, error) {
	recipientStr, _ := bech32.Encode("age", r.TheirPublicKey)
	return age.ParseX25519Recipient(recipientStr)
}

func (r *Fido2HmacRecipient) String() string {
	requirePinByte := byte(0)
	if r.RequirePin {
		requirePinByte = byte(1)
	}

	version := make([]byte, 2)
	binary.BigEndian.PutUint16(version, r.Version)

	switch r.Version {
	case 1:
		data := slices.Concat(
			version,
			[]byte{requirePinByte},
			r.CredId,
		)

		s, _ := bech32.Encode(RECIPIENT_HRP, data)
		return s
	case 2:
		data := slices.Concat(
			version,
			r.TheirPublicKey,
			[]byte{requirePinByte},
			r.Salt,
			r.CredId,
		)

		s, _ := bech32.Encode(RECIPIENT_HRP, data)
		return s
	default:
		return ""
	}
}

func (r *Fido2HmacRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	switch r.Version {
	case 1:
		identity := &Fido2HmacIdentity{
			Version:    1,
			RequirePin: r.RequirePin,
			CredId:     r.CredId,
			Plugin:     r.Plugin,
			UI:         r.UI,
			Device:     r.Device,
		}

		stanzas, err := identity.Wrap(fileKey)
		if err != nil {
			return nil, err
		}

		requirePinByte := byte(0)
		if r.RequirePin {
			requirePinByte = byte(1)
		}

		stanzas[0].Args = append(
			stanzas[0].Args,
			b64.EncodeToString([]byte{requirePinByte}),
			b64.EncodeToString(identity.CredId),
		)

		return stanzas, nil
	case 2:
		x25519Recipient, err := r.X25519Recipient()
		if err != nil {
			return nil, err
		}

		x25519Stanzas, err := x25519Recipient.Wrap(fileKey)
		if err != nil {
			return nil, err
		}

		requirePinByte := byte(0)
		if r.RequirePin {
			requirePinByte = byte(1)
		}

		version := make([]byte, 2)
		binary.BigEndian.PutUint16(version, uint16(STANZA_FORMAT_VERSION))

		stanzaArgs := make([]string, 5)
		stanzaArgs[0] = b64.EncodeToString(version)
		stanzaArgs[1] = x25519Stanzas[0].Args[0]
		stanzaArgs[2] = b64.EncodeToString([]byte{requirePinByte})
		stanzaArgs[3] = b64.EncodeToString(r.Salt)
		stanzaArgs[4] = b64.EncodeToString(r.CredId)

		stanza := &age.Stanza{
			Type: PLUGIN_NAME,
			Args: stanzaArgs,
			Body: x25519Stanzas[0].Body,
		}

		return []*age.Stanza{stanza}, nil
	default:
		return nil, fmt.Errorf("cannot to wrap to recipient with format version %x", r.Version)
	}
}
