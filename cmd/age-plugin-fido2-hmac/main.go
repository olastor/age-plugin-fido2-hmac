package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	page "filippo.io/age/plugin"
	"github.com/olastor/age-plugin-fido2-hmac/pkg/plugin"
	"github.com/olastor/go-libfido2"
)

var Version string

const USAGE = `Usage:
  age-plugin-fido2-hmac [-a ALG] [-r RP_ID] [-s] -g
  age-plugin-fido2-hmac [-r RP_ID] -l
  age-plugin-fido2-hmac -m

Options:
    -g, --generate        Generate new credentials interactively.
    -l, --list            List all discoverable credentials on the token.
    -m, --magic-identity  Print the magic identity to use when no identity is required.
    -a, --algorithm       Choose a specific algorithm when creating the fido2 credential.
                          Can be one of 'es256', 'eddsa', or 'rs256'. Default: es256
    -r, --rp-id           Relying party ID for discoverable credentials.
                          Default: age-encryption.org
    -s, --symmetric       Use symmetric encryption.
    --export-secret-key   Export the secret key for the selected credential instead of the public key.
    -v, --version         Show the version.
    -h, --help            Show this help message.

Examples:
  $ age-plugin-fido2-hmac -g > identity.txt
  $ cat identity.txt | grep 'public key' | grep -oP 'age1.*' > recipient.txt
  $ echo 'secret' | age -R recipient.txt -o secret.enc
  $ age -d -i identity.txt secret.enc # when you created an identity
  $ age -d -j fido2-hmac secret.enc # when there is no identity
  $ age-plugin-fido2-hmac -l # list credentials on token for default RP
  $ age-plugin-fido2-hmac -r myapp.com -l # list credentials for specific RP and optionally select a credential to show recipient and identity
  $ age-plugin-fido2-hmac -r myapp.com -l --export-secret-key # export the raw secret key for the selected credential

Environment Variables:

  FIDO2_TOKEN     This variable can be used to force a specific device path. Please note that
                  /dev/hid* paths are ephemeral and fido2 tokens (mostly) have no identifier.
                  Therefore, it's in general not recommended to use this environment variable.`

func parseAlgorithm(algorithmFlag string) (libfido2.CredentialType, error) {
	if algorithmFlag == "" {
		return libfido2.ES256, nil
	}

	switch strings.TrimSpace(strings.ToLower(algorithmFlag)) {
	case "es256":
		return libfido2.ES256, nil
	case "rs256":
		return libfido2.RS256, nil
	case "eddsa":
		return libfido2.EDDSA, nil
	default:
		return 0, fmt.Errorf("unknown algorithm: \"%s\"", algorithmFlag)
	}
}

func main() {
	var (
		pluginFlag          string
		algorithmFlag       string
		generateFlag        bool
		listFlag            bool
		helpFlag            bool
		versionFlag         bool
		symmetricFlag       bool
		exportSecretKeyFlag bool
		deprecatedMagicFlag bool
		rpIdFlag            string
	)

	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", USAGE) }

	flag.StringVar(&pluginFlag, "age-plugin", "", "")

	flag.StringVar(&algorithmFlag, "a", "es256", "")
	flag.StringVar(&algorithmFlag, "algorithm", "es256", "")

	flag.StringVar(&rpIdFlag, "r", plugin.DEFAULT_RELYING_PARTY, "")
	flag.StringVar(&rpIdFlag, "rp-id", plugin.DEFAULT_RELYING_PARTY, "")

	flag.BoolVar(&generateFlag, "g", false, "")
	flag.BoolVar(&generateFlag, "generate", false, "")
	flag.BoolVar(&generateFlag, "n", false, "")

	flag.BoolVar(&listFlag, "l", false, "")
	flag.BoolVar(&listFlag, "list", false, "")

	flag.BoolVar(&deprecatedMagicFlag, "m", false, "")
	flag.BoolVar(&deprecatedMagicFlag, "magic-identity", false, "")

	flag.BoolVar(&symmetricFlag, "s", false, "")
	flag.BoolVar(&symmetricFlag, "symmetric", false, "")

	flag.BoolVar(&versionFlag, "v", false, "")
	flag.BoolVar(&versionFlag, "version", false, "")

	flag.BoolVar(&exportSecretKeyFlag, "export-secret-key", false, "")

	flag.BoolVar(&helpFlag, "h", false, "")
	flag.BoolVar(&helpFlag, "help", false, "")

	flag.Parse()

	if helpFlag {
		flag.Usage()
		os.Exit(0)
	}

	if deprecatedMagicFlag {
		fmt.Print("AGE-PLUGIN-FIDO2-HMAC-1VE5KGMEJ945X6CTRM2TF76")
		os.Exit(0)
	}

	if listFlag {
		ui := &plugin.TerminalUserInterface{}
		err := plugin.ListCredentials(rpIdFlag, exportSecretKeyFlag, ui)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed: %s\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// TODO: validate RP ID

	if generateFlag {
		algorithm, err := parseAlgorithm(algorithmFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed: %s", err)
			os.Exit(1)
		}

		ui := &plugin.TerminalUserInterface{}
		recipientStr, identityStr, err := plugin.NewCredentials(algorithm, symmetricFlag, rpIdFlag, ui)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed: %s", err)
			os.Exit(1)
		}

		if identityStr != "" {
			fmt.Fprintf(os.Stdout, "# public key: %s\n%s\n", recipientStr, identityStr)
		} else {
			fmt.Fprint(os.Stdout, "# for decryption, use `age -d -j fido2-hmac` without any identity file.\n")
			fmt.Fprintf(os.Stdout, "# public key: %s\n%s\n", recipientStr, identityStr)
		}

		os.Exit(0)
	}

	if pluginFlag == "recipient-v1" {
		p, err := page.New("fido2-hmac")
		if err != nil {
			os.Exit(1)
		}
		p.HandleRecipient(func(data []byte) (age.Recipient, error) {
			r, err := plugin.ParseFido2HmacRecipient(page.EncodeRecipient(plugin.PLUGIN_NAME, data))
			if err != nil {
				return nil, err
			}

			if r.Version == 1 {
				r.Device, err = plugin.FindDevice(50*time.Second, p.DisplayMessage)
				if err != nil {
					return nil, err
				}
			}

			r.Plugin = p
			return r, nil
		})
		p.HandleIdentityAsRecipient(func(data []byte) (age.Recipient, error) {
			i, err := plugin.ParseFido2HmacIdentity(page.EncodeIdentity(plugin.PLUGIN_NAME, data))
			if err != nil {
				return nil, err
			}

			i.Device, err = plugin.FindDevice(50*time.Second, p.DisplayMessage)
			if err != nil {
				return nil, err
			}

			i.Plugin = p

			return i, nil
		})
		if exitCode := p.RecipientV1(); exitCode != 0 {
			os.Exit(exitCode)
		}
		os.Exit(0)
	}

	if pluginFlag == "identity-v1" {
		p, err := page.New("fido2-hmac")
		if err != nil {
			os.Exit(1)
		}
		p.HandleIdentity(func(data []byte) (age.Identity, error) {
			i, err := plugin.ParseFido2HmacIdentity(page.EncodeIdentity(plugin.PLUGIN_NAME, data))
			if err != nil {
				return nil, err
			}

			i.Device, err = plugin.FindDevice(50*time.Second, p.DisplayMessage)
			if err != nil {
				return nil, err
			}

			i.Plugin = p
			return i, nil
		})
		if exitCode := p.IdentityV1(); exitCode != 0 {
			os.Exit(exitCode)
		}
		os.Exit(0)
	}

	if versionFlag && Version != "" {
		fmt.Println(Version)
		os.Exit(0)
	}

	flag.Usage()
	os.Exit(1)
}
