package cmd

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/urfave/cli/v2"
	"gopkg.in/virgil.v5/cryptoimpl"

	"github.com/VirgilSecurity/virgil-cli/utils"
)

func Sign() *cli.Command {
	return &cli.Command{
		Name:      "sign",
		ArgsUsage: "[pr_key]",
		Usage:     "Sign data",
		Flags: []cli.Flag{&cli.StringFlag{Name: "o", Usage: "destination file name"},
			&cli.StringFlag{Name: "key", Usage: "private key file"},
			&cli.StringFlag{Name: "p", Usage: "private key password"},
			&cli.StringFlag{Name: "i", Usage: "input file"},
		},
		Action: func(context *cli.Context) error {
			pass := utils.ReadFlagOrDefault(context, "p", "")

			destinationFileName := utils.ReadFlagOrDefault(context, "o", "")
			dataToSign, err := utils.ReadFileFlagOrParamOrFromConsole(context, "i", "data", "Enter data to sign")
			if err != nil {
				return err
			}
			keyFileName := utils.ReadFlagOrDefault(context, "key", "")
			privateKeyString, err := utils.ReadKeyStringFromFile(context, keyFileName)
			if err != nil {
				return err
			}

			var writer io.Writer = os.Stdout
			if destinationFileName != "" {
				var file *os.File
				file, err = os.Create(destinationFileName)
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

			signature, err := SignFunc(privateKeyString, pass, dataToSign)

			if err != nil {
				return err
			}

			_, err = fmt.Fprint(writer, base64.StdEncoding.EncodeToString(signature))
			if err != nil {
				return err
			}
			fmt.Println()

			return err
		},
	}
}

func SignFunc(privateKeyString, password string, data []byte) (publicKey []byte, err error) {
	pk, err := cryptoimpl.DecodePrivateKey([]byte(privateKeyString), []byte(password))

	if err != nil {
		return nil, errors.New("can't parse private key (may be key password required)")
	}

	return crypto.Sign(data, pk)
}
