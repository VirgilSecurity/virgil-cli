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
			dataToEncrypt, err := utils.ReadFileFlagOrParamOrFromConsole(context, "i", "inp", "data to decrypt")
			if err != nil {
				return err
			}

			keyFileNames := context.StringSlice("key")
			if len(keyFileNames) == 0 {
				return errors.New("key file isn't specified (use -key)")
			}

			pubKeyStrings := make([]string, len(keyFileNames))
			for i, f := range keyFileNames {
				pubKeyStrings[i], err = utils.ReadKeyStringFromFile(context, f)
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

			encData, err := EncryptFunc(dataToEncrypt, pubKeyStrings)

			if err != nil {
				return err
			}

			_, err = fmt.Fprint(writer, base64.StdEncoding.EncodeToString(encData))
			if err != nil {
				return err
			}
			fmt.Println()

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
			return nil, errors.New("can't import public key")
		}
	}

	return crypto.Encrypt(data, pkk...)
}
