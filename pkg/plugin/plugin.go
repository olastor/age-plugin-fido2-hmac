package plugin

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"

	"filippo.io/age"
	page "filippo.io/age/plugin"
	"github.com/olastor/age-plugin-fido2-hmac/internal/bech32"
	"github.com/olastor/age-plugin-fido2-hmac/internal/mlock"
	"github.com/olastor/go-libfido2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
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
func (i *Fido2HmacIdentity) obtainSecretFromToken(pin string) (string, error) {
	if i.Device == nil {
		return pin, fmt.Errorf("device not specified, cannot obtain secret.")
	}

	if i.RequirePin && pin == "" {
		msg := "Please enter your PIN:"
		if i.Plugin != nil {
			var err error
			pin, err = i.RequestSecret(msg)
			if err != nil {
				return pin, err
			}
		} else {
			fmt.Fprintf(os.Stderr, "[*] %s\n", msg)
			pinBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				return pin, err
			}

			pin = string(pinBytes)
		}
	}

	err := i.DisplayMessage("Please touch your token")
	if err != nil {
		return pin, err
	}

	if i.RequirePin {
		i.secretKey, err = getHmacSecret(i.Device, i.CredId, i.Salt, pin)
	} else {
		i.secretKey, err = getHmacSecret(i.Device, i.CredId, i.Salt, "")
	}

	if err != nil {
		return pin, err
	}

	err = mlock.Mlock(i.secretKey)
	if err != nil {
		err = i.DisplayMessage(fmt.Sprintf("Warning: Failed to call mlock: %s", err))
		if err != nil {
			return pin, err
		}
	}

	return pin, nil
}

func (i *Fido2HmacIdentity) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	switch i.Version {
	case 1:
		i.Nonce = make([]byte, 12)
		if _, err := rand.Read(i.Nonce); err != nil {
			return nil, err
		}

		if i.Nonce == nil || len(i.Nonce) != 12 {
			return nil, fmt.Errorf("incomplete identity, missing or invalid nonce for encryption")
		}

		i.Salt = make([]byte, 32)
		if _, err := rand.Read(i.Salt); err != nil {
			return nil, err
		}

		_, err := i.obtainSecretFromToken("")
		if err != nil {
			return nil, err
		}

		if i.secretKey == nil || len(i.secretKey) != 32 {
			return nil, fmt.Errorf("incomplete identity, missing or invalid secret key")
		}

		aead, err := chacha20poly1305.New(i.secretKey)
		if err != nil {
			return nil, err
		}

		ciphertext := aead.Seal(nil, i.Nonce, fileKey, nil)

		stanzaArgs := make([]string, 2)
		stanzaArgs[0] = b64.EncodeToString(i.Salt)
		stanzaArgs[1] = b64.EncodeToString(i.Nonce)

		stanza := &age.Stanza{
			Type: PLUGIN_NAME,
			Args: stanzaArgs,
			Body: ciphertext,
		}

		return []*age.Stanza{stanza}, nil
	case 2:
		_, err := i.obtainSecretFromToken("")
		if err != nil {
			return nil, err
		}

		if i.secretKey == nil || len(i.secretKey) != 32 {
			return nil, fmt.Errorf("incomplete identity, missing or invalid secret key")
		}

		recipient, err := i.Recipient()
		if err != nil {
			return nil, err
		}

		x25519Recipient, err := recipient.X25519Recipient()
		if err != nil {
			return nil, err
		}

		// encrypting with an identity means we can use an X25519 stanza
		return x25519Recipient.Wrap(fileKey)
	default:
		return nil, fmt.Errorf("unsupported recipient version %x", i.Version)
	}
}

func (i *Fido2HmacIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	var pluginStanzas []*Fido2HmacStanza
	var x25519Stanzas []*age.Stanza

	for _, stanza := range stanzas {
		if stanza.Type == PLUGIN_NAME {
			stanzaData, err := ParseFido2HmacStanza(stanza)
			if err != nil {
				return nil, err
			}

			pluginStanzas = append(pluginStanzas, stanzaData)
		} else if stanza.Type == "X25519" && i.Version == 2 {
			x25519Stanzas = append(x25519Stanzas, stanza)
		}
	}

	if len(pluginStanzas)+len(x25519Stanzas) == 0 {
		return nil, fmt.Errorf("no stanza is supported")
	}

	// this mixes up the indexes, so don't use them for errors
	sort.SliceStable(pluginStanzas, func(k, l int) bool {
		// make sure to first try the identities without pin
		return !pluginStanzas[k].RequirePin
	})

	// only ask once for the pin if needed and store it here temporarily thereafter
	pin := ""

	var err error

	// if the version is two and there is a cred id we expect to unwrap x25519 stanzas
	if i.Version == 2 && i.CredId != nil && len(x25519Stanzas) > 0 {
		if i.secretKey == nil {
			pin, err = i.obtainSecretFromToken(pin)
			if err != nil {
				if errors.Is(err, libfido2.ErrNoCredentials) {
					// since the cred ID is the same for all stanzas and it does not match the token,
					// we can tell the controller to try the next identity
					return nil, age.ErrIncorrectIdentity
				}

				return nil, err
			}
		}

		x25519Identity, err := i.X25519Identity()
		if err != nil {
			return nil, err
		}

		fileKey, err := x25519Identity.Unwrap(x25519Stanzas)
		i.ClearSecret()

		if err == nil {
			// do not return an error here because it might be that there is
			// still another plugin stanza that does not match the identity,
			// but can decrypt with the fido2 token "standalone"
			return fileKey, nil
		}
	}

	for _, fidoStanza := range pluginStanzas {
		if fidoStanza.CredId == nil && (i.CredId == nil || fidoStanza.Version != i.Version) {
			// incompatible: cred id needs to exists in either stanza or identity
			// if the stanza contains the cred id, then we can basically ignore the identity
			// because all relevant data is in the stanza. but if the stanza does not include
			// the cred id, then the identity needs to hold it and must have a matching version
			continue
		}

		// some fields need to be copied over from the stanza
		// create a temporary identity with this fields to preserve
		// the original field values of i
		id := *i
		id.Salt = fidoStanza.Salt
		id.Nonce = fidoStanza.Nonce
		if i.CredId == nil {
			id.Version = fidoStanza.Version
			id.CredId = fidoStanza.CredId
			id.RequirePin = fidoStanza.RequirePin
		}

		if !(i.Version == 2 && i.secretKey != nil && slices.Equal(i.CredId, id.CredId)) {
			if (i.RequirePin || fidoStanza.RequirePin) && pin == "" {
				pin, err = i.RequestSecret("Please enter you PIN:")
				if err != nil {
					return nil, err
				}
			}

			// needs to be called for every stanza because at least the salt changed
			pin, err = id.obtainSecretFromToken(pin)
			if err != nil {
				if errors.Is(err, libfido2.ErrNoCredentials) {
					// just because this one stanza didn't match the token doesn't mean
					// any of the other stanzas left don't match. do not error here early!
					continue
				}

				return nil, err
			}
		}

		switch id.Version {
		case 1:
			aead, err := chacha20poly1305.New(id.secretKey)
			if err != nil {
				return nil, err
			}

			plaintext, err := aead.Open(nil, id.Nonce, fidoStanza.Body, nil)
			mlock.Mlock(plaintext)

			if err != nil {
				continue
			}

			return plaintext, nil
		case 2:
			x25519Identity, err := id.X25519Identity()
			if err != nil {
				return nil, err
			}

			plaintext, err := x25519Identity.Unwrap([]*age.Stanza{&age.Stanza{
				Type: "X25519",
				Args: []string{string(fidoStanza.X25519Share)},
				Body: fidoStanza.Body,
			}})

			if err != nil {
				// TODO: differentiate error handling?
				return nil, err
			}

			return plaintext, nil
		default:
			return nil, fmt.Errorf("unsupported identity version %x", i.Version)
		}
	}

	return nil, age.ErrIncorrectIdentity
}

func (i *Fido2HmacIdentity) ClearSecret() {
	if i.secretKey != nil {
		for j := 0; j < cap(i.secretKey); j++ {
			i.secretKey[j] = 0
		}
	}

	i.secretKey = nil
}

func (i *Fido2HmacIdentity) DisplayMessage(msg string) error {
	if i.Plugin != nil {
		err := i.Plugin.DisplayMessage(msg)
		if err != nil {
			return err
		}
	} else {
		fmt.Fprintf(os.Stderr, "[*] %s\n", msg)
	}

	return nil
}

func (i *Fido2HmacIdentity) RequestSecret(msg string) (result string, err error) {
	if i.Plugin != nil {
		var err error
		result, err = i.Plugin.RequestValue(msg, true)
		if err != nil {
			return "", err
		}
	} else {
		fmt.Fprintf(os.Stderr, "[*] %s\n", msg)
		resultBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", err
		}

		result = string(resultBytes)
	}

	return
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
