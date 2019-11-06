package keygen

import (
	"encoding/base64"
	"fmt"
	"gopkg.in/urfave/cli.v2"
	"gopkg.in/virgil.v5/cryptoimpl"
)

//Generates a new Virgil Storage key pair
func VirgilStorage() *cli.Command {
	return &cli.Command{
		Name:    "signing",
		Aliases: []string{"vs"},
		Usage:   "Generates a new Virgil Storage key pair",
		Action: func(context *cli.Context) error {
			
			return PrintSigningKey()
		},
	}
}

func PrintSigningKey() error {
	keyPair, err := cryptoimpl.NewKeypair()

	if err != nil {
		return err
	}

	prKey, err := keyPair.PrivateKey().Encode(nil)
	if err != nil {
		return err
	}

	fmt.Println("VS." + base64.StdEncoding.EncodeToString(prKey))

	return nil
}
