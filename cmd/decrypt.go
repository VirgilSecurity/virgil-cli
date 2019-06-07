package cmd

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/VirgilSecurity/virgil-cli/utils"
	"gopkg.in/virgil.v5/cryptoimpl"
	"io"
	"io/ioutil"
	"os"

	"gopkg.in/urfave/cli.v2"
)

func Decrypt() *cli.Command {
	return &cli.Command{
		Name:      "decrypt",
		ArgsUsage: "[pr_key]",
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
			pass := utils.ReadFlagOrDefault(context, "p", "")

			inputFileName := utils.ReadFlagOrDefault(context, "i", "")
			if inputFileName == "" {
				return errors.New("input file isn't specified (use -i)")
			}

			privateKeyString, err := utils.ReadKeyFromFileOrParamOrFromConsole(context, keyFileName, "pr_key", "private key")
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
			data, err := ioutil.ReadFile(inputFileName)
			if err != nil {
				return err
			}
			key, err := DecryptFunc(privateKeyString, pass, data)

			if err != nil {
				return err
			}

			_, err = fmt.Fprint(writer, string(key))
			if err != nil {
				return err
			}

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
