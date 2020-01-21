package keygen

import (
	"encoding/base64"
	"fmt"

	"github.com/urfave/cli/v2"
)

// VirgilStorage generates a new Virgil Storage key pair
func VirgilStorage() *cli.Command {
	return &cli.Command{
		Name:    "signing",
		Aliases: []string{"vs"},
		Usage:   "Generates a new Virgil Storage key pair",
		Action: func(context *cli.Context) error {
			return printSigningKey()
		},
	}
}

func printSigningKey() error {
	sk, _, err := generateKeypairEncoded()
	if err != nil {
		return err
	}

	fmt.Println("VS." + base64.StdEncoding.EncodeToString(sk))

	return nil
}
