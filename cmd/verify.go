package cmd

import (
	"encoding/base64"
	"fmt"
	"github.com/VirgilSecurity/virgil-cli/utils"
	"gopkg.in/virgil.v5/cryptoimpl"
	"io/ioutil"

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

			keyFileName := utils.ReadFlagOrDefault(context, "key", "")
			inputFileName := utils.ReadFlagOrDefault(context, "i", "")
			signatureFileName := utils.ReadFlagOrDefault(context, "s", "")

			publicKeyString, err := utils.ReadKeyFromFileOrParamOrFromConsole(context, keyFileName, "pub_key", "public key")
			if err != nil {
				return err
			}

			data, err := ioutil.ReadFile(inputFileName)
			if err != nil {
				return err
			}

			signature, err := ioutil.ReadFile(signatureFileName)
			if err != nil {
				return err
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
	dd, err := base64.StdEncoding.DecodeString(string(data))

	if err != nil {
		return err
	}
	ss, err := base64.StdEncoding.DecodeString(string(signature))

	if err != nil {
		return err
	}

	return crypto.VerifySignature(dd, ss, pk)
}
