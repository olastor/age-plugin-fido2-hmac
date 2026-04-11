package main

import (
	"bufio"
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
  age-plugin-fido2-hmac [-s] [-p] [-a ALG] -g
  age-plugin-fido2-hmac -y [-i IDENTITY]
  age-plugin-fido2-hmac -m

Options:
    -g, --generate        Generate new credentials interactively.
    -s, --symmetric       Use symmetric encryption and use a new salt for every encryption.
                          The token must be present for every operation.
    -p, --post-quantum    Use post-quantum MLKEM768-X25519 hybrid encryption instead of X25519.
    -y                    Read an identity file and output the corresponding recipient.
                          Reads from stdin if no -i flag is given.
    -i                    Identity file to read (used with -y).
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
		identityFileFlag    string
		generateFlag        bool
		convertFlag         bool
		helpFlag            bool
		versionFlag         bool
		symmetricFlag       bool
		postQuantumFlag     bool
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

	flag.BoolVar(&postQuantumFlag, "p", false, "")
	flag.BoolVar(&postQuantumFlag, "post-quantum", false, "")

	flag.BoolVar(&convertFlag, "y", false, "")
	flag.StringVar(&identityFileFlag, "i", "", "")

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

		x25519Recipient, hybridRecipient, fido2HmacRecipient, fido2HmacIdentity, err := plugin.NewCredentialsCli(algorithm, symmetricFlag, postQuantumFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed: %s", err)
			os.Exit(1)
		}

		recipientStr := ""
		identityStr := ""

		if fido2HmacRecipient != nil {
			recipientStr = fido2HmacRecipient.String()
		}

		if x25519Recipient != nil {
			recipientStr = x25519Recipient.String()
		}

		if hybridRecipient != nil {
			recipientStr = hybridRecipient.String()
		}

		if fido2HmacIdentity != nil {
			identityStr = fido2HmacIdentity.String()
		}

		if identityStr != "" {
			_, _ = fmt.Fprintf(os.Stdout, "# public key: %s\n%s\n", recipientStr, identityStr)
		} else {
			_, _ = fmt.Fprint(os.Stdout, "# for decryption, use `age -d -j fido2-hmac` without any identity file.\n")
			_, _ = fmt.Fprintf(os.Stdout, "# public key: %s\n%s\n", recipientStr, identityStr)
		}

		os.Exit(0)
	}

	if convertFlag {
		var input *os.File
		if identityFileFlag != "" {
			f, err := os.Open(identityFileFlag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to open identity file: %s\n", err)
				os.Exit(1)
			}
			defer f.Close()
			input = f
		} else {
			input = os.Stdin
		}

		// scan for identity lines
		var identityStr string
		scanner := bufio.NewScanner(input)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			if strings.HasPrefix(strings.ToUpper(line), "AGE-PLUGIN-FIDO2-HMAC-") {
				identityStr = line
				break
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read identity: %s\n", err)
			os.Exit(1)
		}

		if identityStr == "" {
			fmt.Fprintf(os.Stderr, "No fido2-hmac identity found in input\n")
			os.Exit(1)
		}

		identity, err := plugin.ParseFido2HmacIdentity(identityStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse identity: %s\n", err)
			os.Exit(1)
		}

		if identity.CredId == nil {
			fmt.Fprintf(os.Stderr, "Cannot convert a dataless identity to a recipient\n")
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "Please insert your token...\n")
		device, err := plugin.FindDevice(50*time.Second, func(msg string) error {
			fmt.Fprintf(os.Stderr, "%s\n", msg)
			return nil
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to find device: %s\n", err)
			os.Exit(1)
		}
		identity.Device = device

		printf := func(format string, v ...any) {
			fmt.Fprintf(os.Stderr, format, v...)
		}
		ui := page.NewTerminalUI(printf, printf)
		identity.UI = ui

		pin, err := identity.ObtainSecretFromToken("")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to obtain secret: %s\n", err)
			os.Exit(1)
		}
		_ = pin

		recipient, err := identity.Recipient()
		identity.ClearSecret()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to derive recipient: %s\n", err)
			os.Exit(1)
		}

		switch identity.Version {
		case 1:
			fmt.Println(recipient.String())
		case 2:
			x25519Recipient, err := recipient.X25519Recipient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to encode recipient: %s\n", err)
				os.Exit(1)
			}
			fmt.Println(x25519Recipient.String())
		case 3:
			hybridRecipient, err := recipient.HybridRecipient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to encode recipient: %s\n", err)
				os.Exit(1)
			}
			fmt.Println(hybridRecipient.String())
		default:
			fmt.Println(recipient.String())
		}

		os.Exit(0)
	}

	if pluginFlag == "recipient-v1" {
		p, err := page.New("fido2-hmac")
		if err != nil {
			os.Exit(1)
		}
		p.HandleRecipientEncoding(func(recipient string) (age.Recipient, error) {
			r, err := plugin.ParseFido2HmacRecipient(recipient)
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
		p.HandleIdentityEncodingAsRecipient(func(identity string) (age.Recipient, error) {
			if plugin.IsDatalessIdentity(identity) {
				// generate a new recipient "on the fly"

				ui := page.ClientUI{
					Confirm: func(name, prompt, yes, no string) (choseYes bool, err error) {
						return p.Confirm(prompt, yes, no)
					},
					RequestValue: func(name, prompt string, secret bool) (string, error) {
						return p.RequestValue(prompt, secret)
					},
					DisplayMessage: func(name, message string) error {
						return p.DisplayMessage(message)
					},
					WaitTimer: func(name string) {
					},
				}

				// even though using a symmetric recipient makes most sense here, the problem is that it
				// would lead to re-asking for the PIN when the plugin controller calls Wrap().
				// One idea might be to save the PIN in the recipient structure or create a custom recipient
				// type and ask for the PIN here, but I'd like to avoid that.
				_, _, fido2HmacRecipient, _, err := plugin.NewCredentials(libfido2.ES256, false, false, &ui, false)
				if err != nil {
					return nil, err
				}

				if fido2HmacRecipient == nil {
					return nil, fmt.Errorf("failed to create fido2 hmac recipient")
				}

				fido2HmacRecipient.Plugin = p
				return fido2HmacRecipient, nil
			}

			i, err := plugin.ParseFido2HmacIdentity(identity)
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
		p.HandleIdentityEncoding(func(identity string) (age.Identity, error) {
			i, err := plugin.ParseFido2HmacIdentity(identity)
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
