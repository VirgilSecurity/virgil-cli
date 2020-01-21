package cmd

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/urfave/cli/v2"
	"gopkg.in/virgil.v5/cryptoimpl"

	"github.com/VirgilSecurity/virgil-cli/utils"
)

func Keygen() *cli.Command {
	return &cli.Command{
		Name:  "keygen",
		Usage: "Generate keypair",
		Flags: []cli.Flag{&cli.StringFlag{Name: "o", Usage: "destination file name"},
			&cli.StringFlag{Name: "p", Usage: "password"}},
		Action: func(context *cli.Context) error {
			pass := utils.ReadFlagOrDefault(context, "p", "")
			key, err := KeygenFunc(pass)
			if err != nil {
				return err
			}

			var writer io.Writer = os.Stdout
			if fileName := utils.ReadFlagOrDefault(context, "o", ""); fileName != "" {
				var file *os.File
				file, err = os.Create(fileName)
				if err != nil {
					return err
				}
				defer func() {
					if ferr := file.Close(); ferr != nil {
						panic(ferr)
					}
				}()

				writer = file
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
