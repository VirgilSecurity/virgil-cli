package keygen

import (
	"encoding/base64"
	"fmt"

	"gopkg.in/urfave/cli.v2"
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
	sk, pk, err := generateKeypairEncoded()
	if err != nil {
		return err
	}

	fmt.Println("BU." + base64.StdEncoding.EncodeToString(pk))
	fmt.Println("private key: " + base64.StdEncoding.EncodeToString(sk))

	return nil
}
