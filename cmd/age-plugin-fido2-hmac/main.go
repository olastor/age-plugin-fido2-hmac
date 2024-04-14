package main

import (
	"flag"
	"fmt"
	"github.com/keys-pub/go-libfido2"
	"github.com/olastor/age-plugin-fido2-hmac/pkg/plugin"
	"github.com/olastor/age-plugin-sss/pkg/sss"
	"os"
	"strings"
)

var Version string

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

	flag.StringVar(&pluginFlag, "age-plugin", "", "Used by age for interacting with the plugin.")
	flag.BoolVar(&generateFlag, "g", false, "Generate a new recipient/identity pair.")
	flag.BoolVar(&generateFlag, "generate", false, "")
	flag.BoolVar(&magicFlag, "m", false, "Print the magic identity to use when no identity is required.")
	flag.BoolVar(&versionFlag, "v", false, "Show the version.")
	flag.BoolVar(&versionFlag, "version", false, "")
	flag.StringVar(&algorithmFlag, "algorithm", "es256", "The algorithm to use ('es256', 'eddsa', 'rs256').")
	flag.BoolVar(&helpFlag, "h", false, "Show this help message.")
	flag.BoolVar(&symmetricFlag, "symmetric", false, "Generate a new salt for every encryption.\nThe token must be present for every operation.")
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
		if err := plugin.RecipientV1(); err != nil {
			sss.SendCommand("error", []byte(err.Error()), false)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if pluginFlag == "identity-v1" {
		if err := plugin.IdentityV1(); err != nil {
			sss.SendCommand("error", []byte(err.Error()), false)
			os.Exit(1)
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
