package cmd

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/urfave/cli.v2"
	"gopkg.in/virgil.v5/cryptoimpl"

	"github.com/VirgilSecurity/virgil-cli/utils"
)

func Decrypt() *cli.Command {
	return &cli.Command{
		Name:      "decrypt",
		ArgsUsage: "[inp]",
		Usage:     "Decrypt data",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "o", Usage: "destination file name"},
			&cli.StringFlag{Name: "key", Usage: "private key file"},
			&cli.StringFlag{Name: "p", Usage: "private key password"},
			&cli.StringFlag{Name: "i", Usage: "input file"},
		},
		Action: func(context *cli.Context) error {
			destinationFileName := utils.ReadFlagOrDefault(context, "o", "")
			keyFileName := utils.ReadFlagOrDefault(context, "key", "")
			if keyFileName == "" {
				return errors.New("key file isn't specified (use -key)")
			}
			pass := utils.ReadFlagOrDefault(context, "p", "")

			dataToDecrypt, err := utils.ReadFileFlagOrParamOrFromConsole(context, "i", "inp", "Enter data to decrypt")
			if err != nil {
				return err
			}

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

			key, err := DecryptFunc(privateKeyString, pass, dataToDecrypt)
			if err != nil {
				return err
			}

			_, err = fmt.Fprint(writer, string(key))
			if err != nil {
				return err
			}
			fmt.Println()

			return nil
		},
	}
}

func DecryptFunc(privateKeyString, password string, data []byte) (publicKey []byte, err error) {
	pk, err := cryptoimpl.DecodePrivateKey([]byte(privateKeyString), []byte(password))

	if err != nil {
		if err != nil {
			return nil, errors.New("can't import private key")
		}
	}

	dd, err := base64.StdEncoding.DecodeString(string(data))

	if err != nil {
		return nil, err
	}

	return crypto.Decrypt(dd, pk)
}
