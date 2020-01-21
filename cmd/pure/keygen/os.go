package keygen

import (
	"encoding/base64"
	"fmt"

	"github.com/urfave/cli/v2"
	"gopkg.in/virgil.v5/cryptoimpl"
)

// OwnSigningKey is generates a new own signing key
func OwnSigningKey() *cli.Command {
	return &cli.Command{
		Name:        "own",
		Aliases:     []string{"os"},
		Usage:       "Generates a new own signing key",
		Description: "Own signing key is used to sign data that is encrypted",
		Action: func(context *cli.Context) error {
			return printOwnSigningKey()
		},
	}
}

func printOwnSigningKey() error {
	keyPair, err := cryptoimpl.NewKeypair()

	if err != nil {
		return err
	}

	prKey, err := keyPair.PrivateKey().Encode(nil)
	if err != nil {
		return err
	}

	fmt.Println("OS." + base64.StdEncoding.EncodeToString(prKey))

	return nil
}
