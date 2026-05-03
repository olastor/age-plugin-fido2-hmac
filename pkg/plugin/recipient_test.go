package plugin

import (
	"crypto/rand"
	"testing"

	"filippo.io/age"
	"github.com/olastor/age-plugin-fido2-hmac/internal/bech32"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecipientFormat(t *testing.T) {
	for _, requirePin := range []bool{true, false} {
		nativePubKey := make([]byte, 32)
		_, err := rand.Read(nativePubKey)
		require.NoError(t, err)

		salt := make([]byte, 32)
		_, err = rand.Read(salt)
		require.NoError(t, err)

		credId := make([]byte, 50)
		_, err = rand.Read(credId)
		require.NoError(t, err)

		rec := &Fido2HmacRecipient{
			Version:      2,
			NativePubKey: nativePubKey,
			Salt:         salt,
			CredId:       credId,
			RequirePin:   requirePin,
		}

		rec2, err := ParseFido2HmacRecipient(rec.String())
		require.NoError(t, err)

		assert.Equal(t, rec.NativePubKey, rec2.NativePubKey, "public key should not change")
		assert.Equal(t, rec.Salt, rec2.Salt, "salt should not change")
		assert.Equal(t, rec.CredId, rec2.CredId, "cred id should not change")
		assert.Equal(t, rec.RequirePin, rec2.RequirePin, "require pin should not change")
		assert.Equal(t, rec, rec2, "recipients should be equal")
	}
}

func TestRecipient_Wrap_Version2(t *testing.T) {
	// Generate a valid X25519 key pair to extract a real public key
	x25519Identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	_, nativePubKey, err := bech32.Decode(x25519Identity.Recipient().String())
	require.NoError(t, err)

	salt := make([]byte, 32)
	_, err = rand.Read(salt)
	require.NoError(t, err)

	credId := make([]byte, 50)
	_, err = rand.Read(credId)
	require.NoError(t, err)

	rec := &Fido2HmacRecipient{
		Version:      2,
		NativePubKey: nativePubKey,
		Salt:         salt,
		CredId:       credId,
		RequirePin:   false,
	}

	fileKey := make([]byte, 16)
	_, err = rand.Read(fileKey)
	require.NoError(t, err)

	stanzas, err := rec.Wrap(fileKey)
	require.NoError(t, err)
	require.Len(t, stanzas, 1)
	assert.Equal(t, PLUGIN_NAME, stanzas[0].Type)
	assert.Len(t, stanzas[0].Args, 5)

	// Verify the underlying native X25519 stanza can be unwrapped with the private key
	nativeStanza := &age.Stanza{
		Type: "X25519",
		Args: []string{stanzas[0].Args[1]},
		Body: stanzas[0].Body,
	}
	fileKey2, err := x25519Identity.Unwrap([]*age.Stanza{nativeStanza})
	require.NoError(t, err)
	assert.Equal(t, fileKey, fileKey2)
}

func TestRecipient_Wrap_Version3_PQ(t *testing.T) {
	// Generate a valid hybrid identity to extract a real public key
	hybridIdentity, err := age.GenerateHybridIdentity()
	require.NoError(t, err)

	_, nativePubKey, err := bech32.Decode(hybridIdentity.Recipient().String())
	require.NoError(t, err)

	salt := make([]byte, 32)
	_, err = rand.Read(salt)
	require.NoError(t, err)

	credId := make([]byte, 50)
	_, err = rand.Read(credId)
	require.NoError(t, err)

	rec := &Fido2HmacRecipient{
		Version:      3,
		NativePubKey: nativePubKey,
		Salt:         salt,
		CredId:       credId,
		RequirePin:   false,
	}

	fileKey := make([]byte, 16)
	_, err = rand.Read(fileKey)
	require.NoError(t, err)

	stanzas, err := rec.Wrap(fileKey)
	require.NoError(t, err)
	require.Len(t, stanzas, 1)
	assert.Equal(t, PLUGIN_NAME, stanzas[0].Type)
	assert.Len(t, stanzas[0].Args, 5)

	// Verify the underlying native mlkem768x25519 stanza can be unwrapped with the private key
	nativeStanza := &age.Stanza{
		Type: "mlkem768x25519",
		Args: []string{stanzas[0].Args[1]},
		Body: stanzas[0].Body,
	}
	fileKey2, err := hybridIdentity.Unwrap([]*age.Stanza{nativeStanza})
	require.NoError(t, err)
	assert.Equal(t, fileKey, fileKey2)
}

func TestRecipient_Wrap_Version1_WithMock(t *testing.T) {
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	mockDevice := &MockFido2Device{
		HmacSecret: secret,
	}

	credId := make([]byte, 50)
	_, err = rand.Read(credId)
	require.NoError(t, err)

	rec := &Fido2HmacRecipient{
		Version:    1,
		CredId:     credId,
		RequirePin: false,
		Device:     mockDevice,
		UI:         newMockUI(nil, func(msg string) error { return nil }, nil),
	}

	fileKey := make([]byte, 16)
	_, err = rand.Read(fileKey)
	require.NoError(t, err)

	stanzas, err := rec.Wrap(fileKey)
	require.NoError(t, err)
	require.Len(t, stanzas, 1)
	assert.Equal(t, PLUGIN_NAME, stanzas[0].Type)
	assert.Len(t, stanzas[0].Args, 4)
}
