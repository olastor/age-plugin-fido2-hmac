package plugin

import (
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	page "filippo.io/age/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newMockUI(
	requestSecret func(string) (string, error),
	displayMessage func(string) error,
	confirm func(string) (bool, error),
) *page.ClientUI {
	return &page.ClientUI{
		RequestValue: func(name, prompt string, secret bool) (string, error) {
			if requestSecret != nil {
				return requestSecret(prompt)
			}
			return "", nil
		},
		DisplayMessage: func(name, message string) error {
			if displayMessage != nil {
				return displayMessage(message)
			}
			return nil
		},
		Confirm: func(name, prompt, yes, no string) (bool, error) {
			if confirm != nil {
				return confirm(prompt)
			}
			return false, nil
		},
		WaitTimer: func(name string) {},
	}
}

func TestFormattingV1(t *testing.T) {
	testRecipients := []string{
		"age1fido2-hmac1qqqsrgcqtpax86tmayc47ve7p300dpxj20uxrmwj0dc83z9qygw2gadfw395jr4fqjjc0r7vdn4qkaftxzjeemycun4ll9kp38x3czl4jk5jdqx969yjfeahhrqf8q9qgyf6s45d5avhser2uk8t6f5xy0e58qduv8m3hhk0w0zupfftexnzweth5fumd9mtmr7v6xlek8n6yespf3saz75wdmp2452v78nfxqjsfrmccw30j9aw7vezt5u7rkcu6uhr5n8a",
		"age1fido2-hmac1qqqspgcqtpa0kc9v37necfmsj2r22dnw2f8hlj9f4r3y70r57stv9r4tt2a3wjk7jzdzl0yguvhk98vafkuvq9ud2sl73jpdz3etefdhy5pa0yejjtw6h3jvlcrph5kfdzgxk5y97zhhqnq4jhjm8vyr65wfu0dp2gw8hfqaazqc3dsqtr3qktzmjf594u87v98z0aa3z8vwpwgpfjym66eznchm6gpr4kkpwqjszpeuudu2nlpve3t3q4mpeeacrymhu5th",
	}
	testIdentities := []string{
		"AGE-PLUGIN-FIDO2-HMAC-1QQQSRGCQTPAYYLSEE84VECJJTC2E2DCSP4WY04SZ05Q98QURMU4Z79T6VFQ6R8T4PX97N6CARHPASL509TG83TWVMMYE6XT6UV0497G43DSA4RSXTTKQXWU0YMTNLH9CNX5C0V7SUED4UJSM35YJASRUXEZZHPKWUN4WT88JVCGLVNC6SUJWN43TZNQ9WL3R5TJPCVYKNX0EC2QPF38SSHMD3PQJ4U9260RHGQJSDJ7JPGZG6Q9MDV3RCQRPT2FUVYUP0YCK",
		"AGE-PLUGIN-FIDO2-HMAC-1QQQSPGCQTPAP3Y2TAG9EZHHZVE9AUM9XATHE68A43X26RSQ8D4XRY90YKE4GX5XDZZYP6XXJWEN39FWJPX6KSTYVX3L4VH3JAMGDQAK6PPKQFEK8RXXLRMFFZJ2FDHDCHR6QPCCMYDZ0TJWPUKZY4D0U2TPJ5A9WRDL64K33UC4YKFG6RD8757PPVSX3556FA3NJZSXZZ53N6HSPFJST4FSXDV3XZC287FPDUQJSC5YNR4V994G83T7USMKLR2DLUSCFHEA6",
	}

	for _, r := range testRecipients {
		parsed, err := ParseFido2HmacRecipient(r)
		require.NoError(t, err)
		assert.Equal(t, r, parsed.String(), "recipient string should not change")
	}

	for _, i := range testIdentities {
		parsed, err := ParseFido2HmacIdentity(i)
		require.NoError(t, err)
		assert.Equal(t, i, parsed.String(), "identity string should not change")
	}
}

func TestWrapping(t *testing.T) {
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
		RequirePin: false,
	}

	rec, err := id.Recipient()
	require.NoError(t, err)

	fileKey := make([]byte, 16)
	_, err = rand.Read(fileKey)
	require.NoError(t, err)

	stanzas, err := rec.Wrap(fileKey)
	require.NoError(t, err)

	fileKey2, err := id.Unwrap(stanzas)
	require.NoError(t, err)
	assert.Equal(t, fileKey, fileKey2, "file keys should match")
}

func TestParseIdentities_Basic(t *testing.T) {
	id1 := &Fido2HmacIdentity{
		Version: 2,
		Salt:    make([]byte, 32),
		CredId:  make([]byte, 50),
	}
	id2 := &Fido2HmacIdentity{
		Version: 2,
		Salt:    make([]byte, 32),
		CredId:  make([]byte, 50),
	}

	input := fmt.Sprintf("# comment\n\n%s\n%s\n", id1.String(), id2.String())
	reader := strings.NewReader(input)

	ids, err := ParseIdentities(reader)
	require.NoError(t, err)
	assert.Len(t, ids, 2)
	assert.Equal(t, id1.String(), ids[0].String())
	assert.Equal(t, id2.String(), ids[1].String())
}

func TestParseIdentities_Empty(t *testing.T) {
	reader := strings.NewReader("")
	_, err := ParseIdentities(reader)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no identities found")
}
