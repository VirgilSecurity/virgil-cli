package keygen

import (
	"encoding/base64"
	"fmt"

	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto/wrapper/phe"
	"github.com/urfave/cli/v2"

	"github.com/VirgilSecurity/virgil-cli/cmd/kms"
)

// Secret generates secret key
func Secret() *cli.Command {
	return &cli.Command{
		Name:    "secret",
		Aliases: []string{"sk"},
		Usage:   "Generate a new Secret key",
		Action: func(context *cli.Context) error {
			return printSecretKey()
		},
	}
}

func printSecretKey() error {
	pheClient := phe.NewPheClient()
	if err := pheClient.SetupDefaults(); err != nil {
		return err
	}

	pheKey, err := pheClient.GenerateClientPrivateKey()
	if err != nil {
		return err
	}
	kmsKey, err := kms.GenerateKMSPrivateKey()
	if err != nil {
		return err
	}
	fmt.Printf(
		"SK.1.%s.%s\n",
		base64.StdEncoding.EncodeToString(pheKey),
		base64.StdEncoding.EncodeToString(kmsKey),
	)
	return nil
}
