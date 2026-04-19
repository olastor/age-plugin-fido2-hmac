package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	page "filippo.io/age/plugin"
	"github.com/olastor/age-plugin-fido2-hmac/pkg/plugin"
	"github.com/olastor/go-libfido2"
)

var Version string

// ConvertIdentitiesToRecipients reads identities from input and prints recipients to stdout.
// If path is "-" or empty, reads from stdin. If usePQ is true, v2 identities use hybrid encryption.
func ConvertIdentitiesToRecipients(path string, usePQ bool) error {
	var input io.Reader = os.Stdin
	if path != "" && path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open identity file: %w", err)
		}
		defer f.Close()
		input = f
	}

	identities, err := plugin.ParseIdentities(input)
	if err != nil {
		return fmt.Errorf("failed to parse identities: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Please insert your token...\n")
	device, err := plugin.FindDevice(50*time.Second, func(msg string) error {
		fmt.Fprintf(os.Stderr, "%s\n", msg)
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to find device: %s\n", err)
	}
	printf := func(format string, v ...any) {
		fmt.Fprintf(os.Stderr, format, v...)
	}
	ui := page.NewTerminalUI(printf, printf)

	pin := ""

	for _, i := range identities {
		if i.Version < 3 && i.CredId == nil {
			return fmt.Errorf("data-less identity cannot be converted to recipient")
		}

		// for v2 identities, allow PQ override via flag
		if i.Version == 2 {
			i.PQ = usePQ
		}

		i.UI = ui
		i.Device = device

		if i.RequirePin && pin == "" {
			pin, err = i.RequestSecret("Please enter you PIN:")
			if err != nil {
				return err
			}
		}

		i.LoadSecret(pin)

		recipient, err := i.Recipient()
		if err != nil {
			return fmt.Errorf("failed to derive recipient: %w", err)
		}

		fmt.Println(recipient.String())
	}
	return nil
}

const USAGE = `Usage:
  age-plugin-fido2-hmac [-s] [-a ALG] [-pq] -g
  age-plugin-fido2-hmac -y [FILE]
  age-plugin-fido2-hmac -m

Options:
    -g, --generate        Generate new credentials interactively.
    -s, --symmetric       Use symmetric encryption and use a new salt for every encryption.
                          The token must be present for every operation.
    -pq, --post-quantum   Use post-quantum MLKEM768-X25519 hybrid encryption instead of X25519.
    -y [FILE]             Read an identity file and output the corresponding recipient(s).
                          If FILE is "-" or not provided, reads from stdin.
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
                  Therefore, it's in general not recommended to use this environment variable.

  FIDO2_HMAC_PQ   Set to '1', 'true', or 'yes' to force post-quantum encryption (MLKEM768X25519)
                  when using an identity as recipient. Set to '0', 'false', or 'no' to disable.
                  If not set, you will be prompted interactively.`

func main() {
	var (
		pluginFlag          string
		algorithmFlag       string
		generateFlag        bool
		helpFlag            bool
		versionFlag         bool
		symmetricFlag       bool
		postQuantumFlag     bool
		identityToRecipient string
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

	flag.BoolVar(&postQuantumFlag, "pq", false, "")
	flag.BoolVar(&postQuantumFlag, "post-quantum", false, "")

	flag.StringVar(&identityToRecipient, "y", "", "")

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

		result, err := plugin.NewCredentialsCli(algorithm, symmetricFlag, postQuantumFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed: %s", err)
			os.Exit(1)
		}

		message := fmt.Sprintf("# created: %s\n", time.Now().Format(time.RFC3339))

		if result.Fido2HmacRecipient != nil {
			message += fmt.Sprintf("# public key: %s\n", result.Fido2HmacRecipient)
		}

		if result.X25519Recipient != nil {
			message += fmt.Sprintf("# public key: %s\n", result.X25519Recipient)
		}

		if result.HybridRecipient != nil {
			message += fmt.Sprintf("# public key (pq safe): %s\n", result.HybridRecipient)
		}

		if result.Fido2HmacIdentity != nil {
			message += result.Fido2HmacIdentity.String()
			message += "\n"
		} else {
			message += "# for decryption, use `age -d -j fido2-hmac` without any identity file.\n"
		}

		_, _ = fmt.Fprint(os.Stdout, message)

		os.Exit(0)
	}

	if identityToRecipient != "" {
		if err := ConvertIdentitiesToRecipients(identityToRecipient, postQuantumFlag); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
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
				result, err := plugin.NewCredentials(libfido2.ES256, false, false, &ui, false)
				if err != nil {
					return nil, err
				}

				if result.Fido2HmacRecipient == nil {
					return nil, fmt.Errorf("failed to create fido2 hmac recipient")
				}

				result.Fido2HmacRecipient.Plugin = p
				return result.Fido2HmacRecipient, nil
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

			// determine PQ preference: env var overrides interactive prompt
			if i.Version == 2 {
				usePQ := false
				envPQ := os.Getenv("FIDO2_HMAC_PQ")
				switch strings.ToLower(envPQ) {
				case "1", "true", "yes":
					usePQ = true
				case "0", "false", "no":
					usePQ = false
				default:
					// env not set or invalid value, ask interactively
					var err error
					usePQ, err = p.Confirm("Use post-quantum encryption (MLKEM768X25519)?", "yes", "no")
					if err != nil {
						return nil, err
					}
				}
				i.PQ = usePQ
			}

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
