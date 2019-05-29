package cmd

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"gopkg.in/virgil.v5/cryptoimpl"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/VirgilSecurity/virgil-cli/utils"

	"gopkg.in/urfave/cli.v2"
)

var crypto  =  cryptoimpl.NewVirgilCrypto()

func Encrypt() *cli.Command {
	return &cli.Command{
		Name:      "encrypt",
		ArgsUsage: "[pub_key]",
		Usage:     "Encrypt data",
		Flags: []cli.Flag{&cli.StringFlag{Name: "o", Usage: "destination file name"},
			&cli.StringFlag{Name: "key", Usage: "public key file"},
			&cli.StringFlag{Name: "i", Usage: "input file"},
		},
		Action: func(context *cli.Context) error {


			destinationFileName := utils.ReadFlagOrDefault(context, "o", "")
			inputFileName := utils.ReadFlagOrDefault(context, "i", "")
			keyFileName := utils.ReadFlagOrDefault(context, "key", "")

			publicKeyString := ""
			if keyFileName != "" {

				f, err := os.Open(keyFileName)
				if err != nil {
					return err
				}
				defer func() {
					if err := f.Close(); err != nil {
						panic(err)
					}
				}()

				scanner := bufio.NewScanner(f)
				for scanner.Scan() {
					t := scanner.Text()
					if strings.Contains(t, "BEGIN ") {
						continue
					}
					publicKeyString = t
					break
				}

			} else {
				publicKeyString = utils.ReadParamOrDefaultOrFromConsole(context, "pub_key", "public key", "")
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
			key, err := EncryptFunc(publicKeyString, data)

			if err != nil {
				return err
			}

			_, err = fmt.Fprintln(writer, base64.StdEncoding.EncodeToString(key))
			if err != nil {
				return err
			}
			return err
		},
	}
}

func EncryptFunc(publicKeyString string, data []byte) (publicKey []byte, err error) {

	pk, err := cryptoimpl.DecodePublicKey([]byte(publicKeyString))

	if err != nil {
		return nil, err
	}

	return crypto.Encrypt(data, pk)
}
