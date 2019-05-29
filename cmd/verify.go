package cmd

import (
	"bufio"
	"fmt"
	"gopkg.in/virgil.v5/cryptoimpl"
	"io/ioutil"
	"os"
	"strings"

	"github.com/VirgilSecurity/virgil-cli/utils"

	"gopkg.in/urfave/cli.v2"
)

func Verify() *cli.Command {
	return &cli.Command{
		Name:      "verify",
		ArgsUsage: "[pub_key]",
		Usage:     "Verify signature",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "key", Usage: "public key file"},
			&cli.StringFlag{Name: "i", Usage: "input file"},
			&cli.StringFlag{Name: "s", Usage: "signature file"},
		},
		Action: func(context *cli.Context) error {

			inputFileName := utils.ReadFlagOrDefault(context, "i", "")
			signatureFileName := utils.ReadFlagOrDefault(context, "i", "")
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


			data, err := ioutil.ReadFile(inputFileName)
			if err != nil {
				fmt.Print(err)
			}

			signature, err := ioutil.ReadFile(signatureFileName)
			if err != nil {
				fmt.Print(err)
			}
			err = VerifyFunc(publicKeyString, data, signature)

			if err != nil {
				return err
			}

			fmt.Println("Signature OK ")
			return nil
		},
	}
}

func VerifyFunc(publicKeyString string, data, signature []byte) (err error) {

	pk, err := cryptoimpl.DecodePublicKey([]byte(publicKeyString))

	if err != nil {
		return err
	}

	return crypto.VerifySignature(data, signature, pk)
}
