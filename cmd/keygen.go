package cmd

import (
	"encoding/base64"
	"fmt"
	"gopkg.in/virgil.v5/cryptoimpl"
	"io"
	"os"

	"github.com/VirgilSecurity/virgil-cli/utils"

	"gopkg.in/urfave/cli.v2"
)

func Keygen() *cli.Command {
	return &cli.Command{
		Name:      "keygen",
		Usage:     "Generate keypair",
		Flags: []cli.Flag{&cli.StringFlag{Name: "o", Usage: "destination file name"},
			&cli.StringFlag{Name: "p", Usage: "password"}},
		Action: func(context *cli.Context) error {

			pass := utils.ReadFlagOrDefault(context, "p", "")
			key, err := KeygenFunc(pass)

			if err != nil {
				return err
			}
			fileName := utils.ReadFlagOrDefault(context, "o", "")
			var writer io.Writer
			if fileName != "" {
				file, err := os.Create(fileName)
				if err != nil {
					return err
				}
				writer = file
				defer func() {
					if err := file.Close(); err != nil {
						panic(err)
					}
				}()

			} else {
				writer = os.Stdout
			}

			encrypted := " "
			if pass != "" {
				encrypted = " ENCRYPTED "
			}

			_, err = fmt.Fprintf(writer, "-----BEGIN%sPRIVATE KEY-----\n", encrypted)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(writer, base64.StdEncoding.EncodeToString(key))
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(writer, "-----END%sPRIVATE KEY-----\n", encrypted)
			if err != nil {
				return err
			}

			return err
		},
	}
}

func KeygenFunc(password string) (privateKey []byte, err error) {

	keyPair, err := cryptoimpl.NewKeypair()

	if err != nil {
		return nil, err
	}

	prKey, err := keyPair.PrivateKey().Encode([]byte(password))
	if err != nil {
		return nil, err
	}

	return prKey, nil
}
