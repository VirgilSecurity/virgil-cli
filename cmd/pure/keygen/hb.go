package keygen

import (
	"encoding/base64"
	"fmt"

	"gopkg.in/urfave/cli.v2"
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
	sk, pk, err := generateKeypairEncoded()
	if err != nil {
		return err
	}

	fmt.Println("HB." + base64.StdEncoding.EncodeToString(pk))
	fmt.Println("private key: " + base64.StdEncoding.EncodeToString(sk))

	return nil
}
