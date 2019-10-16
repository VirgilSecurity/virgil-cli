package keygen

import (
	"encoding/base64"
	"fmt"
	"gopkg.in/urfave/cli.v2"
	"gopkg.in/virgil.v5/cryptoimpl"
)

//Generates a new  Backup keypair
func Backup() *cli.Command {
	return &cli.Command{
		Name:    "backup",
		Aliases: []string{"bu"},
		Usage:   "Generates a new  Backup keypair ",
		Action: func(context *cli.Context) error {

			return PrintBackupKey()
		},
	}
}

func PrintBackupKey() error {
	keyPair, err := cryptoimpl.NewKeypair()

	if err != nil {
		return err
	}

	prKey, err := keyPair.PrivateKey().Encode([]byte(""))
	if err != nil {
		return err
	}

	pubKey, err := keyPair.PublicKey().Encode()
	fmt.Println("BU." + base64.StdEncoding.EncodeToString(pubKey))
	fmt.Println("private key: " + base64.StdEncoding.EncodeToString(prKey))

	return nil
}
