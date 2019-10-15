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
		Name:    "vskp",
		Aliases: []string{"vs"},
		Usage:   "Generates a new Virgil Storage key pair",
		Action: func(context *cli.Context) error {

			keyPair, err := cryptoimpl.NewKeypair()

			if err != nil {
				return err
			}

			prKey, err := keyPair.PrivateKey().Encode([]byte(""))
			if err != nil {
				return err
			}

			fmt.Println("VS." + base64.StdEncoding.EncodeToString(prKey))

			return nil
		},
	}
}
