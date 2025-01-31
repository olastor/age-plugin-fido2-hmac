package plugin

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"

	"filippo.io/age"
	page "filippo.io/age/plugin"
	"github.com/keys-pub/go-libfido2"
	"github.com/olastor/age-plugin-fido2-hmac/internal/bech32"
)

var b64 = base64.RawStdEncoding.Strict()

const (
	PLUGIN_NAME                  = "fido2-hmac"
	RECIPIENT_HRP                = "age1" + PLUGIN_NAME
	IDENTITY_HRP                 = "age-plugin-" + PLUGIN_NAME + "-"
	RELYING_PARTY                = "age-encryption.org"
	STANZA_FORMAT_VERSION uint16 = 2
)

type Fido2HmacRecipient struct {
	Version        uint16
	TheirPublicKey []byte
	RequirePin     bool
	Salt           []byte
	CredId         []byte
	Plugin         *page.Plugin

	// only when the version is 1, the device must be set
	Device *libfido2.Device
}

type Fido2HmacIdentity struct {
	Version    uint16
	secretKey  []byte
	RequirePin bool
	Salt       []byte
	CredId     []byte
	Plugin     *page.Plugin
	Nonce      []byte
	Device     *libfido2.Device
}

// data structure for stanza with parsed args
type Fido2HmacStanza struct {
	Version     uint16
	RequirePin  bool
	Salt        []byte
	CredId      []byte
	X25519Share string
	Nonce       []byte
	Body        []byte
}

// Checks if an identity is a "data-less" identity. This method is backwards-compatible with older plugin versions that used a custom "magic" identity.
func IsDatalessIdentity(identity string) bool {
	// the first one is the legacy special identity of this plugin
	// the second one is the identity passed from age when using -j
	return identity == "AGE-PLUGIN-FIDO2-HMAC-1VE5KGMEJ945X6CTRM2TF76" || identity == "AGE-PLUGIN-FIDO2-HMAC-188VDVA"
}

func ParseFido2HmacRecipient(recipient string) (*Fido2HmacRecipient, error) {
	hrp, data, err := bech32.Decode(recipient)
	if err != nil {
		return nil, err
	}

	if hrp != RECIPIENT_HRP {
		return nil, fmt.Errorf("malformed recipient %s: invalid type %s", recipient, hrp)
	}

	format_version := binary.BigEndian.Uint16(data[0:2])

	switch format_version {
	case 1:
		return &Fido2HmacRecipient{
			Version:        1,
			TheirPublicKey: nil,
			RequirePin:     data[2] == byte(1),
			Salt:           nil,
			CredId:         data[3:],
		}, nil
	case 2:
		return &Fido2HmacRecipient{
			Version:        2,
			TheirPublicKey: data[2:34],
			RequirePin:     data[34] == byte(1),
			Salt:           data[35:67],
			CredId:         data[67:],
		}, nil
	default:
		return nil, fmt.Errorf("unsupported recipient version %x", format_version)
	}
}

func ParseFido2HmacIdentity(identity string) (*Fido2HmacIdentity, error) {
	if IsDatalessIdentity(identity) {
		return &Fido2HmacIdentity{
			Version: 2,
		}, nil
	}

	hrp, data, err := bech32.Decode(strings.ToLower(identity))
	if err != nil {
		return nil, err
	}

	if hrp != IDENTITY_HRP {
		return nil, fmt.Errorf("malformed identity %s: invalid type %s", identity, hrp)
	}

	format_version := binary.BigEndian.Uint16(data[0:2])

	switch format_version {
	case 1:
		return &Fido2HmacIdentity{
			Version:    1,
			secretKey:  nil,
			RequirePin: data[2] == byte(1),
			Salt:       nil,
			CredId:     data[3:],
		}, nil
	case 2:
		return &Fido2HmacIdentity{
			Version:    2,
			secretKey:  nil,
			RequirePin: data[2] == byte(1),
			Salt:       data[3:35],
			CredId:     data[35:],
		}, nil
	default:
		return nil, fmt.Errorf("unsupported identity version %x", format_version)
	}
}

func ParseFido2HmacStanza(stanza *age.Stanza) (*Fido2HmacStanza, error) {
	stanzaData := &Fido2HmacStanza{Body: stanza.Body}

	stanzaVersionBytes, err := b64.DecodeString(stanza.Args[0])
	if err != nil {
		return nil, err
	}

	// v1 format has no stanza version, so it's recognized by length of salt instead
	if len(stanzaVersionBytes) == 32 {
		stanzaData.Version = 1
	} else {
		stanzaData.Version = binary.BigEndian.Uint16(stanzaVersionBytes)
	}

	switch stanzaData.Version {
	case 1:
		if len(stanza.Args) != 2 && len(stanza.Args) != 4 {
			return nil, fmt.Errorf("invalid length of stanza args: %d", len(stanza.Args))
		}

		stanzaData.Salt, err = b64.DecodeString(stanza.Args[0])
		if err != nil {
			return nil, fmt.Errorf("salt in stanza is malformed")
		}

		stanzaData.Nonce, err = b64.DecodeString(stanza.Args[1])
		if err != nil {
			return nil, fmt.Errorf("nonce in stanza is malformed")
		}

		if len(stanza.Args) == 4 {
			stanzaData.RequirePin = stanza.Args[2] == "AQ"
			stanzaData.CredId, err = b64.DecodeString(stanza.Args[3])
			if err != nil {
				return nil, fmt.Errorf("cred id in stanza is malformed")
			}
		}
	case 2:
		stanzaData.X25519Share = stanza.Args[1]

		requirePin, err := b64.DecodeString(stanza.Args[2])
		if err != nil {
			return nil, fmt.Errorf("require pin flag in stanza is malformed")
		}
		stanzaData.RequirePin = requirePin[0] == byte(1)

		stanzaData.Salt, err = b64.DecodeString(stanza.Args[3])
		if err != nil {
			return nil, fmt.Errorf("salt in stanza is malformed")
		}

		stanzaData.CredId, err = b64.DecodeString(stanza.Args[4])
		if err != nil {
			return nil, fmt.Errorf("cred id in stanza is malformed")
		}

	default:
		return nil, fmt.Errorf("unsupported stanza version %d", stanzaData.Version)
	}

	return stanzaData, nil
}
