package plugin

import (
	"crypto/rand"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentityFormat(t *testing.T) {
	for _, requirePin := range []bool{true, false} {
		secretKey := make([]byte, 32)
		_, err := rand.Read(secretKey)
		require.NoError(t, err)

		salt := make([]byte, 32)
		_, err = rand.Read(salt)
		require.NoError(t, err)

		credId := make([]byte, 50)
		_, err = rand.Read(credId)
		require.NoError(t, err)

		id := &Fido2HmacIdentity{
			Version:    2,
			secretKey:  secretKey,
			Salt:       salt,
			CredId:     credId,
			RequirePin: requirePin,
		}

		id2, err := ParseFido2HmacIdentity(id.String())
		require.NoError(t, err)

		assert.Nil(t, id2.secretKey, "secret key should be cleared after parsing")
		assert.Equal(t, id.Salt, id2.Salt, "salt should not change")
		assert.Equal(t, id.CredId, id2.CredId, "cred id should not change")
		assert.Equal(t, id.RequirePin, id2.RequirePin, "require pin should not change")

		id2.secretKey = secretKey
		assert.Equal(t, id, id2, "identities should be equal after restoring secret key")
	}
}

func TestLoadSecret_Success(t *testing.T) {
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	mockDevice := &MockFido2Device{
		HmacSecret: secret,
	}

	id := &Fido2HmacIdentity{
		Version:    2,
		Salt:       make([]byte, 32),
		CredId:     make([]byte, 50),
		Device:     mockDevice,
		RequirePin: false,
		UI:         newMockUI(nil, nil, nil),
	}

	err = id.LoadSecret("")
	require.NoError(t, err)
	assert.Equal(t, secret, id.secretKey)
}

func TestLoadSecret_AlreadyLoaded(t *testing.T) {
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	mockDevice := &MockFido2Device{
		HmacSecret: []byte("different_secret_12345678901234"),
	}

	id := &Fido2HmacIdentity{
		Version:    2,
		secretKey:  secret, // already loaded
		Salt:       make([]byte, 32),
		CredId:     make([]byte, 50),
		Device:     mockDevice,
		RequirePin: false,
		UI:         newMockUI(nil, nil, nil),
	}

	err = id.LoadSecret("")
	require.NoError(t, err)
	assert.Equal(t, secret, id.secretKey, "secret should remain unchanged when already loaded")
}

func TestLoadSecret_PinRequiredButMissing(t *testing.T) {
	mockDevice := &MockFido2Device{}

	id := &Fido2HmacIdentity{
		Version:    2,
		Salt:       make([]byte, 32),
		CredId:     make([]byte, 50),
		Device:     mockDevice,
		RequirePin: true,
		UI:         newMockUI(nil, nil, nil),
	}

	err := id.LoadSecret("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pin required")
}

func TestObtainSecretFromToken_PinPromptAndCache(t *testing.T) {
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	pinRequested := 0
	mockDevice := &MockFido2Device{
		HmacSecret: secret,
	}

	id := &Fido2HmacIdentity{
		Version:    2,
		Salt:       make([]byte, 32),
		CredId:     make([]byte, 50),
		Device:     mockDevice,
		RequirePin: true,
		UI: newMockUI(func(prompt string) (string, error) {
			pinRequested++
			assert.Contains(t, prompt, "PIN")
			return "1234", nil
		}, nil, nil),
	}

	pin, err := id.obtainSecretFromToken("")
	require.NoError(t, err)
	assert.Equal(t, "1234", pin)
	assert.Equal(t, 1, pinRequested)
	assert.Equal(t, secret, id.secretKey)
}

func TestWrapAndUnwrap_Version2_X25519(t *testing.T) {
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	mockDevice := &MockFido2Device{
		HmacSecret: secret,
	}

	id := &Fido2HmacIdentity{
		Version:    2,
		Salt:       make([]byte, 32),
		CredId:     make([]byte, 50),
		Device:     mockDevice,
		RequirePin: false,
		UI:         newMockUI(nil, func(msg string) error { return nil }, nil),
	}

	// production flow: load secret first, then derive recipient
	_, err = id.obtainSecretFromToken("")
	require.NoError(t, err)
	defer id.ClearSecret()

	rec, err := id.Recipient()
	require.NoError(t, err)

	fileKey := make([]byte, 16)
	_, err = rand.Read(fileKey)
	require.NoError(t, err)

	stanzas, err := rec.Wrap(fileKey)
	require.NoError(t, err)
	require.Len(t, stanzas, 1)
	assert.Equal(t, PLUGIN_NAME, stanzas[0].Type)
	assert.Len(t, stanzas[0].Args, 5)
	assert.NotEmpty(t, stanzas[0].Body)

	fileKey2, err := id.Unwrap(stanzas)
	require.NoError(t, err)
	assert.Equal(t, fileKey, fileKey2)
}

func TestUnwrap_NoMatchingStanzas(t *testing.T) {
	id := &Fido2HmacIdentity{
		Version: 2,
		Salt:    make([]byte, 32),
		CredId:  make([]byte, 50),
	}

	stanzas := []*age.Stanza{
		{Type: "scrypt", Args: []string{"args"}, Body: []byte("body")},
	}

	_, err := id.Unwrap(stanzas)
	require.ErrorIs(t, err, age.ErrIncorrectIdentity)
}

func TestClearSecret_ZeroesMemory(t *testing.T) {
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	id := &Fido2HmacIdentity{
		secretKey: secret,
	}

	id.ClearSecret()

	assert.Nil(t, id.secretKey)
	for i, b := range secret {
		assert.Zero(t, b, "byte %d not zeroed", i)
	}
}

func TestIdentity_SecretKeyNeverSerialized(t *testing.T) {
	secretKey := make([]byte, 32)
	_, err := rand.Read(secretKey)
	require.NoError(t, err)

	id := &Fido2HmacIdentity{
		Version:   2,
		secretKey: secretKey,
		Salt:      make([]byte, 32),
		CredId:    make([]byte, 50),
	}

	str := id.String()
	parsed, err := ParseFido2HmacIdentity(str)
	require.NoError(t, err)
	assert.Nil(t, parsed.secretKey)
}
