package cmd

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/urfave/cli.v2"
	"gopkg.in/virgil.v5/cryptoimpl"

	"github.com/VirgilSecurity/virgil-cli/utils"
)

func Key2Pub() *cli.Command {
	return &cli.Command{
		Name:      "key2pub",
		ArgsUsage: "[prKey]",
		Usage:     "Extract public key",
		Flags: []cli.Flag{&cli.StringFlag{Name: "o", Usage: "destination file name"},
			&cli.StringFlag{Name: "p", Usage: "password"},
			&cli.StringFlag{Name: "i", Usage: "input file"},
		},
		Action: func(context *cli.Context) error {

			pass := utils.ReadFlagOrDefault(context, "p", "")

			destinationFileName := utils.ReadFlagOrDefault(context, "o", "")
			inputFileName := utils.ReadFlagOrDefault(context, "i", "")

			privateKeyString := ""
			if inputFileName != "" {

				f, err := os.Open(inputFileName)
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
					privateKeyString = t
					break
				}

			} else {
				privateKeyString = utils.ReadParamOrDefaultOrFromConsole(context, "prKey", "private key", "")
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
			key, err := Key2PubFunc(privateKeyString, pass)

			if err != nil {
				return err
			}

			_, err = fmt.Fprintf(writer, "-----BEGIN PUBLIC KEY-----\n")
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(writer, base64.StdEncoding.EncodeToString(key))
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(writer, "-----END PUBLIC KEY-----\n")
			if err != nil {
				return err
			}

			return err
		},
	}
}

func Key2PubFunc(privateKeyString, password string) (publicKey []byte, err error) {

	pk, err := cryptoimpl.DecodePrivateKey([]byte(privateKeyString), []byte(password))

	if err != nil {
		return nil, fmt.Errorf("can't parse private key (may be key password required)")
	}

	pubKey, err := pk.ExtractPublicKey()
	if err != nil {
		return nil, err
	}

	return pubKey.Encode()
}
