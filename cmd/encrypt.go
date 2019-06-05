package cmd

import (
	"encoding/base64"
	"fmt"
	"github.com/VirgilSecurity/virgil-cli/utils"
	"gopkg.in/virgil.v5/cryptoimpl"
	"io"
	"io/ioutil"
	"os"

	"gopkg.in/urfave/cli.v2"
)

var crypto = cryptoimpl.NewVirgilCrypto()

func Encrypt() *cli.Command {
	return &cli.Command{
		Name:      "encrypt",
		ArgsUsage: "[pub_key]",
		Usage:     "Encrypt data",
		Flags: []cli.Flag{&cli.StringFlag{Name: "o", Usage: "destination file name"},
			&cli.StringSliceFlag{Name: "key", Usage: "public key file"},
			&cli.StringFlag{Name: "i", Usage: "input file"},
		},
		Action: func(context *cli.Context) error {

			destinationFileName := utils.ReadFlagOrDefault(context, "o", "")
			inputFileName := utils.ReadFlagOrDefault(context, "i", "")
			keyFileNames := context.StringSlice("key")
			// utils.ReadFlagOrDefault(context, "key", "")

			var err error
			pubKeyStrings := make([]string, len(keyFileNames))
			for i, f := range keyFileNames {
				pubKeyStrings[i], err = utils.ReadKeyFromFileOrParamOrFromConsole(context, f, "pub_key", "public key")
				if err != nil {
					return err
				}
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
				fmt.Print(err)
			}
			key, err := EncryptFunc(data, pubKeyStrings)

			if err != nil {
				return err
			}

			_, err = fmt.Fprint(writer, base64.StdEncoding.EncodeToString(key))
			if err != nil {
				return err
			}
			return err
		},
	}
}

func EncryptFunc(data []byte, publicKeysStrings []string) (publicKey []byte, err error) {

	pkk := make([]interface {
		IsPublic() bool
		Identifier() []byte
	}, len(publicKeysStrings))

	for i, s := range publicKeysStrings {
		pkk[i], err = cryptoimpl.DecodePublicKey([]byte(s))
		if err != nil {
			return nil, err
		}
	}

	return crypto.Encrypt(data, pkk...)
}