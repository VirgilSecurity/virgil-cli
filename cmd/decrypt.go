package cmd

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/VirgilSecurity/virgil-cli/utils"
	"gopkg.in/virgil.v5/cryptoimpl"
	"io"
	"os"

	"gopkg.in/urfave/cli.v2"
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

			dataToDecrypt, err := utils.ReadFileFlagOrParamOrFromConsole(context, "i", "inp", "data to decrypt")
			if err != nil {
				return err
			}

			privateKeyString, err := utils.ReadKeyStringFromFile(context, keyFileName)
			if err != nil {
				return err
			}

			var writer io.Writer
			if destinationFileName != "" {
				file, err := os.Create(destinationFileName)
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

			key, err := DecryptFunc(privateKeyString, pass, dataToDecrypt)

			if err != nil {
				return err
			}

			_, err = fmt.Fprint(writer, string(key))
			if err != nil {
				return err
			}
			fmt.Println()

			return err
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
