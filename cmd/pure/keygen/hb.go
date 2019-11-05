package keygen

import (
	"encoding/base64"
	"fmt"

	"gopkg.in/urfave/cli.v2"
	"gopkg.in/virgil.v5/cryptoimpl"
)

// HashesKey generates a new Hashes key pair
func HashesKey() *cli.Command {
	return &cli.Command{
		Name:    "hashes",
		Aliases: []string{"hb"},
		Usage:   "Generates a new Hashes key pair",
		Action: func(context *cli.Context) error {

			return PrintHBKey()
		},
	}
}

func PrintHBKey() error {
	keyPair, err := cryptoimpl.NewKeypair()

	if err != nil {
		return err
	}

	prKey, err := keyPair.PrivateKey().Encode(nil)
	if err != nil {
		return err
	}

	pubKey, err := keyPair.PublicKey().Encode()
	if err != nil {
		return err
	}
	fmt.Println("HB." + base64.StdEncoding.EncodeToString(pubKey))
	fmt.Println("private key: " + base64.StdEncoding.EncodeToString(prKey))

	return nil
}
