package keygen

import (
	"encoding/base64"
	"fmt"

	"gopkg.in/urfave/cli.v2"
	"gopkg.in/virgil.v5/cryptoimpl"
)

// Backup generates a new  Backup keypair
func Backup() *cli.Command {
	return &cli.Command{
		Name:    "backup",
		Aliases: []string{"bu"},
		Usage:   "Generates a new  Backup keypair ",
		Action: func(context *cli.Context) error {

			return printBackupKey()
		},
	}
}

func printBackupKey() error {
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
	fmt.Println("BU." + base64.StdEncoding.EncodeToString(pubKey))
	fmt.Println("private key: " + base64.StdEncoding.EncodeToString(prKey))

	return nil
}
