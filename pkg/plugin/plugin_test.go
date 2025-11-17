package plugin

import (
	"crypto/rand"
	"reflect"
	"testing"
)

func TestRecipientFormat(t *testing.T) {
	for _, requirePin := range []bool{true, false} {
		theirPublicKey := make([]byte, 32)
		if _, err := rand.Read(theirPublicKey); err != nil {
			t.Error(err)
		}

		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			t.Error(err)
		}

		credId := make([]byte, 50)
		if _, err := rand.Read(credId); err != nil {
			t.Error(err)
		}

		rec := &Fido2HmacRecipient{
			Version:        2,
			TheirPublicKey: theirPublicKey,
			Salt:           salt,
			CredId:         credId,
			RequirePin:     requirePin,
		}

		rec2, err := ParseFido2HmacRecipient(rec.String())
		if err != nil {
			t.Error(err)
		}

		if !reflect.DeepEqual(rec.TheirPublicKey, rec2.TheirPublicKey) {
			t.Error("Public key changed")
		}
		if !reflect.DeepEqual(rec.Salt, rec2.Salt) {
			t.Error("Salt changed")
		}
		if !reflect.DeepEqual(rec.CredId, rec2.CredId) {
			t.Error("Cred ID changed")
		}
		if !reflect.DeepEqual(rec.RequirePin, rec2.RequirePin) {
			t.Error("RequirePIN changed")
		}
		if !reflect.DeepEqual(rec, rec2) {
			t.Error("Recipients have changed")
		}
	}
}

func TestIdentityFormat(t *testing.T) {
	for _, requirePin := range []bool{true, false} {
		secretKey := make([]byte, 32)
		if _, err := rand.Read(secretKey); err != nil {
			t.Error(err)
		}

		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			t.Error(err)
		}

		credId := make([]byte, 50)
		if _, err := rand.Read(credId); err != nil {
			t.Error(err)
		}

		id := &Fido2HmacIdentity{
			Version:    2,
			secretKey:  secretKey,
			Salt:       salt,
			CredId:     credId,
			RequirePin: requirePin,
			RpId:       "age-encryption.org",
		}

		id2, err := ParseFido2HmacIdentity(id.String())
		if err != nil {
			t.Error(err)
		}

		if id2.secretKey != nil {
			t.Error("Secret key not cleared")
		}
		if !reflect.DeepEqual(id.Salt, id2.Salt) {
			t.Error("Salt changed")
		}
		if !reflect.DeepEqual(id.CredId, id2.CredId) {
			t.Error("Cred ID changed")
		}
		if !reflect.DeepEqual(id.RequirePin, id2.RequirePin) {
			t.Error("RequirePIN changed")
		}

		id2.secretKey = secretKey

		if !reflect.DeepEqual(id, id2) {
			t.Error("Identities have changed")
		}
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
		if err != nil {
			t.Error(err)
		}

		if !reflect.DeepEqual(r, parsed.String()) {
			t.Error("Recipient string changed")
		}
	}

	for _, i := range testIdentities {
		parsed, err := ParseFido2HmacIdentity(i)
		if err != nil {
			t.Error(err)
		}

		if !reflect.DeepEqual(i, parsed.String()) {
			t.Error("Identity string changed")
		}
	}
}

func TestWrapping(t *testing.T) {
	for i := 0; i < 1; i++ {
		secretKey := make([]byte, 32)
		if _, err := rand.Read(secretKey); err != nil {
			t.Error(err)
		}

		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			t.Error(err)
		}

		credId := make([]byte, 50)
		if _, err := rand.Read(credId); err != nil {
			t.Error(err)
		}

		requirePin := i%2 == 0

		id := &Fido2HmacIdentity{
			Version:    2,
			secretKey:  secretKey,
			Salt:       salt,
			CredId:     credId,
			RequirePin: requirePin,
		}

		rec, err := id.Recipient()
		if err != nil {
			t.Error(err)
		}

		fileKey := make([]byte, 16)
		if _, err := rand.Read(fileKey); err != nil {
			t.Error(err)
		}

		stanzas, err := rec.Wrap(fileKey)
		if err != nil {
			t.Error(err)
		}

		fileKey2, err := id.Unwrap(stanzas)
		if err != nil {
			t.Error(err)
		}

		if !reflect.DeepEqual(fileKey, fileKey2) {
			t.Error("File keys do not match")
		}
	}
}
