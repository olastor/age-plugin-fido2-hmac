package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
	page "filippo.io/age/plugin"
	"github.com/keys-pub/go-libfido2"
	"github.com/olastor/age-plugin-fido2-hmac/pkg/plugin"
)

var Version string

const USAGE = `Usage:
  age-plugin-fido2-hmac [-s] [-a ALG] -g
  age-plugin-fido2-hmac -m

Options:
    -g, --generate        Generate new credentials interactively.
    -s, --symmetric       Use symmetric encryption and use a new salt for every encryption.
                          The token must be present for every operation.
    -a, --algorithm       Choose a specific algorithm when creating the fido2 credential.
                          Can be one of 'es256', 'eddsa', or 'rs256'. Default: es256
    -m, --magic-identity  Print the magic identity to use when no identity is required.
    -v, --version         Show the version.
    -h, --help            Show this help message.

Examples:
  $ age-plugin-fido2-hmac -g > identity.txt
  $ cat identity.txt | grep 'public key' | grep -oP 'age1.*' > recipient.txt
  $ echo 'secret' | age -R recipient.txt -o secret.enc
  $ age -d -i identity.txt secret.enc`

func main() {
	var (
		pluginFlag    string
		algorithmFlag string
		generateFlag  bool
		magicFlag     bool
		helpFlag      bool
		versionFlag   bool
		symmetricFlag bool
	)

	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", USAGE) }

	flag.StringVar(&pluginFlag, "age-plugin", "", "")

	flag.StringVar(&algorithmFlag, "a", "es256", "")
	flag.StringVar(&algorithmFlag, "algorithm", "es256", "")

	flag.BoolVar(&generateFlag, "g", false, "")
	flag.BoolVar(&generateFlag, "generate", false, "")
	flag.BoolVar(&generateFlag, "n", false, "")

	flag.BoolVar(&magicFlag, "m", false, "")
	flag.BoolVar(&magicFlag, "magic-identity", false, "")

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

	if magicFlag {
		fmt.Printf("%s", plugin.MAGIC_IDENTITY)
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

		plugin.GenerateNewCli(algorithm, symmetricFlag)
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
			return r, nil
		})
		p.HandleIdentityAsRecipient(func(data []byte) (age.Recipient, error) {
			i, err := plugin.ParseFido2HmacIdentity(page.EncodeIdentity("fido2-hmac", data))

			if err != nil {
				return nil, err
			}

			i.Plugin = p
			i.ObtainSecretFromToken("")

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
