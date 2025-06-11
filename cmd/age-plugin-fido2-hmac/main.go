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
  age-plugin-fido2-hmac [-s] [-a ALG] -g
  age-plugin-fido2-hmac -m

Options:
    -g, --generate        Generate new credentials interactively.
    -s, --symmetric       Use symmetric encryption and use a new salt for every encryption.
                          The token must be present for every operation.
    -m, --magic-identity  Print the magic identity to use when no identity is required.
    -a, --algorithm       Choose a specific algorithm when creating the fido2 credential.
                          Can be one of 'es256', 'eddsa', or 'rs256'. Default: es256
    -v, --version         Show the version.
    -h, --help            Show this help message.

Examples:
  $ age-plugin-fido2-hmac -g > identity.txt # only contains an identity if chosen by user
  $ cat identity.txt | grep 'public key' | grep -oP 'age1.*' > recipient.txt
  $ echo 'secret' | age -R recipient.txt -o secret.enc
  $ age -d -i identity.txt secret.enc # when you created an identity
  $ age -d -j fido2-hmac secret.enc # when there is no identity

Environment Variables:

  FIDO2_TOKEN     This variable can be used to force a specific device path. Please note that
                  /dev/hid* paths are ephemeral and fido2 tokens (mostly) have no identifier.
                  Therefore, it's in general not recommended to use this environment variable.`

func main() {
	var (
		pluginFlag          string
		algorithmFlag       string
		generateFlag        bool
		helpFlag            bool
		versionFlag         bool
		symmetricFlag       bool
		deprecatedMagicFlag bool
	)

	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", USAGE) }

	flag.StringVar(&pluginFlag, "age-plugin", "", "")

	flag.StringVar(&algorithmFlag, "a", "es256", "")
	flag.StringVar(&algorithmFlag, "algorithm", "es256", "")

	flag.BoolVar(&generateFlag, "g", false, "")
	flag.BoolVar(&generateFlag, "generate", false, "")
	flag.BoolVar(&generateFlag, "n", false, "")

	flag.BoolVar(&deprecatedMagicFlag, "m", false, "")
	flag.BoolVar(&deprecatedMagicFlag, "magic-identity", false, "")

	flag.BoolVar(&symmetricFlag, "s", false, "")
	flag.BoolVar(&symmetricFlag, "symmetric", false, "")

	flag.BoolVar(&versionFlag, "v", false, "")
	flag.BoolVar(&versionFlag, "version", false, "")

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

	if generateFlag {
		algorithm := libfido2.ES256

		if algorithmFlag != "" {
			switch strings.TrimSpace(strings.ToLower(algorithmFlag)) {
			case "es256":
				algorithm = libfido2.ES256
			case "rs256":
				algorithm = libfido2.RS256
			case "eddsa":
				algorithm = libfido2.EDDSA
			default:
				fmt.Fprintf(os.Stderr, "Unknown algorithm: \"%s\"", algorithmFlag)
				os.Exit(1)
			}
		}

		recipientStr, identityStr, err := plugin.NewCredentialsCli(algorithm, symmetricFlag)
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
			r, err := plugin.ParseFido2HmacRecipient(page.EncodeRecipient("fido2-hmac", data))
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
			i, err := plugin.ParseFido2HmacIdentity(page.EncodeIdentity("fido2-hmac", data))
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
			i, err := plugin.ParseFido2HmacIdentity(page.EncodeIdentity("fido2-hmac", data))
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
