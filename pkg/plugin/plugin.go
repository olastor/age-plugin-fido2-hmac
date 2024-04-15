package plugin

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"filippo.io/age"
	"fmt"
	"github.com/olastor/age-plugin-fido2-hmac/internal/bech32"
	"github.com/olastor/age-plugin-fido2-hmac/internal/mlock"
	"github.com/olastor/age-plugin-sss/pkg/sss"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
	"os"
	"slices"
	"strings"
)

var b64 = base64.RawStdEncoding.Strict()

const (
	PLUGIN_NAME                  = "fido2-hmac"
	RECIPIENT_HRP                = "age1" + PLUGIN_NAME
	IDENTITY_HRP                 = "age-plugin-" + PLUGIN_NAME + "-"
	RELYING_PARTY                = "age-encryption.org"
	STANZA_FORMAT_VERSION uint16 = 2
	MAGIC_IDENTITY               = "AGE-PLUGIN-FIDO2-HMAC-1VE5KGMEJ945X6CTRM2TF76"
)

type Fido2HmacRecipient struct {
	Version        uint16
	TheirPublicKey []byte
	RequirePin     bool
	Salt           []byte
	CredId         []byte
}

type Fido2HmacIdentity struct {
	Version    uint16
	secretKey  []byte
	RequirePin bool
	Salt       []byte
	CredId     []byte

	legacyNonce []byte
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

func StanzaToIdentity(stanza *age.Stanza) (*Fido2HmacIdentity, error) {
	stanzaVersionBytes, err := b64.DecodeString(stanza.Args[0])
	if err != nil {
		return nil, err
	}

	if len(stanzaVersionBytes) == 32 {
		// v1 format
		salt, err1 := b64.DecodeString(stanza.Args[0])
		nonce, err2 := b64.DecodeString(stanza.Args[1])

		if err := errors.Join(err1, err2); err != nil {
			return nil, err
		}

		identity := &Fido2HmacIdentity{
			Version:     1,
			RequirePin:  false,
			Salt:        salt,
			CredId:      nil,
			legacyNonce: nonce,
		}

		if len(stanza.Args) == 4 {
			identity.RequirePin = stanza.Args[2] == "AQ"
			credId, err3 := b64.DecodeString(stanza.Args[3])
			if err3 != nil {
				return nil, err
			}
			identity.CredId = credId
		}

		return identity, nil
	}

	stanzaVersion := binary.BigEndian.Uint16(stanzaVersionBytes)
	if stanzaVersion != STANZA_FORMAT_VERSION {
		return nil, fmt.Errorf("Unsupported stanza version %x", stanzaVersion)
	}

	requirePin, err1 := b64.DecodeString(stanza.Args[2])
	salt, err2 := b64.DecodeString(stanza.Args[3])
	credId, err3 := b64.DecodeString(stanza.Args[4])

	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, err
	}

	return &Fido2HmacIdentity{
		RequirePin: requirePin[0] == byte(1),
		Salt:       salt,
		CredId:     credId,
	}, nil
}

func StanzaArgsLine(stanza *age.Stanza) string {
	line := fmt.Sprintf("recipient-stanza 0 %s", stanza.Type)

	for _, arg := range stanza.Args {
		line = fmt.Sprintf("%s %s", line, arg)
	}

	return line
}

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
	if r.Version != 2 {
		return nil, fmt.Errorf("cannot to wrap to recipient with format version %x", r.Version)
	}

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
}

func (i *Fido2HmacIdentity) X25519Identity() (*age.X25519Identity, error) {
	identityStr, _ := bech32.Encode("AGE-SECRET-KEY-", i.secretKey)
	return age.ParseX25519Identity(strings.ToUpper(identityStr))
}

func (i *Fido2HmacIdentity) Recipient() (*Fido2HmacRecipient, error) {
	switch i.Version {
	case 1:
		return &Fido2HmacRecipient{
			Version:    1,
			RequirePin: i.RequirePin,
			CredId:     i.CredId,
		}, nil
	case 2:
		x25519Identity, err := i.X25519Identity()
		if err != nil {
			return nil, err
		}

		_, theirPublicKey, err := bech32.Decode(x25519Identity.Recipient().String())
		if err != nil {
			return nil, err
		}

		if err != nil {
			return nil, err
		}

		return &Fido2HmacRecipient{
			Version:        2,
			TheirPublicKey: theirPublicKey,
			RequirePin:     i.RequirePin,
			Salt:           i.Salt,
			CredId:         i.CredId,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported identity version %x", i.Version)
	}
}

// the pin can be passed if it's known already to avoid re-asking, but it's optional
func (i *Fido2HmacIdentity) ObtainSecretFromToken(isPlugin bool, pin string) error {
	device, err := FindDevice()
	if err != nil {
		return err
	}

	if device == nil {
		msg := "Please insert your token now."

		if isPlugin {
			sss.SendCommand("msg", []byte(msg), true)
		} else {
			fmt.Fprintf(os.Stderr, "[*] %s\n", msg)
		}
		device, err = WaitForDevice(50)

		if err != nil {
			return err
		}
	}

	if i.RequirePin && pin == "" {
		msg := "Please enter you PIN"
		if isPlugin {
			pin, err = sss.RequestValue(msg, true)
			if err != nil {
				return err
			}
		} else {
			fmt.Fprintf(os.Stderr, "[*] %s\n", msg)
			pinBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				return err
			}

			pin = string(pinBytes)
		}
	}

	msg := "Please touch your token..."
	if isPlugin {
		sss.SendCommand("msg", []byte(msg), true)
	} else {
		fmt.Fprintf(os.Stderr, "[*] %s\n", msg)
	}

	i.secretKey, err = GetHmacSecret(device, i.CredId, i.Salt, pin)
	if err != nil {
		return err
	}

	err = mlock.Mlock(i.secretKey)
	if err != nil {
		msg := fmt.Sprintf("Warning: Failed to call mlock: %s", err)
		if isPlugin {
			sss.SendCommand("msg", []byte(msg), true)
		} else {
			fmt.Fprintf(os.Stderr, "[*] %s\n", msg)
		}
	}

	return nil
}

func (i *Fido2HmacIdentity) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	switch i.Version {
	case 1:
		if i.secretKey == nil || len(i.secretKey) != 32 {
			return nil, fmt.Errorf("incomplete identity, missing or invalid secret key")
		}

		i.legacyNonce = make([]byte, 12)
		if _, err := rand.Read(i.legacyNonce); err != nil {
			return nil, err
		}

		if i.legacyNonce == nil || len(i.legacyNonce) != 12 {
			return nil, fmt.Errorf("incomplete identity, missing or invalid nonce for encryption")
		}

		aead, err := chacha20poly1305.New(i.secretKey)
		if err != nil {
			return nil, err
		}

		ciphertext := aead.Seal(nil, i.legacyNonce, fileKey, nil)
		if err != nil {
			return nil, err
		}

		requirePinByte := byte(0)
		if i.RequirePin {
			requirePinByte = byte(1)
		}

		stanzaArgs := make([]string, 4)
		stanzaArgs[0] = b64.EncodeToString(i.Salt)
		stanzaArgs[1] = b64.EncodeToString(i.legacyNonce)
		stanzaArgs[2] = b64.EncodeToString([]byte{requirePinByte})
		stanzaArgs[3] = b64.EncodeToString(i.CredId)

		stanza := &age.Stanza{
			Type: PLUGIN_NAME,
			Args: stanzaArgs,
			Body: ciphertext,
		}

		return []*age.Stanza{stanza}, nil
	case 2:
		recipient, err := i.Recipient()
		if err != nil {
			return nil, err
		}

		return recipient.Wrap(fileKey)
	default:
		return nil, fmt.Errorf("unsupported recipient version %x", i.Version)
	}
}

func (i *Fido2HmacIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	var x25519Stanzas []*age.Stanza

	for _, stanza := range stanzas {
		if stanza.Type == PLUGIN_NAME {
			stanzaVersion, err := b64.DecodeString(stanza.Args[0])
			if err != nil {
				return nil, err
			}

			if len(stanzaVersion) == 32 {
				// v1 format has no stanza version, recognized by length of salt
				if i.Version != 1 {
					continue
				} else {
					aead, err := chacha20poly1305.New(i.secretKey)
					if err != nil {
						return nil, err
					}

					plaintext, err := aead.Open(nil, i.legacyNonce, stanza.Body, nil)
					mlock.Mlock(plaintext)

					if err != nil {
						return nil, err
					}

					return plaintext, nil
				}
			}

			x25519Stanzas = append(x25519Stanzas, &age.Stanza{
				Type: "X25519",
				Args: []string{stanza.Args[1]},
				Body: stanza.Body,
			})
		} else if stanza.Type == "X25519" {
			x25519Stanzas = append(x25519Stanzas, stanza)
		}
	}

	x25519Identity, err := i.X25519Identity()
	if err != nil {
		return nil, err
	}

	return x25519Identity.Unwrap(x25519Stanzas)
}

func (i *Fido2HmacIdentity) ClearSecret() {
	if i.secretKey != nil {
		for j := 0; j < cap(i.secretKey); j++ {
			i.secretKey[j] = 0
		}
	}

	i.secretKey = nil
}

func (i *Fido2HmacIdentity) String() string {
	requirePinByte := byte(0)
	if i.RequirePin {
		requirePinByte = byte(1)
	}

	version := make([]byte, 2)
	binary.BigEndian.PutUint16(version, i.Version)

	switch i.Version {
	case 1:
		data := slices.Concat(
			version,
			[]byte{requirePinByte},
			i.CredId,
		)

		s, _ := bech32.Encode(IDENTITY_HRP, data)

		return strings.ToUpper(s)
	case 2:
		data := slices.Concat(
			version,
			[]byte{requirePinByte},
			i.Salt,
			i.CredId,
		)

		s, _ := bech32.Encode(IDENTITY_HRP, data)

		return strings.ToUpper(s)
	default:
		return ""
	}
}
