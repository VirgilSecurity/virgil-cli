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


func Sign() *cli.Command {
	return &cli.Command{
		Name:      "sign",
		ArgsUsage: "[pr_key]",
		Usage:     "Decrypt data",
		Flags: []cli.Flag{&cli.StringFlag{Name: "o", Usage: "destination file name"},
			&cli.StringFlag{Name: "key", Usage: "private key file"},
			&cli.StringFlag{Name: "p", Usage: "private key password"},
			&cli.StringFlag{Name: "i", Usage: "input file"},
		},
		Action: func(context *cli.Context) error {

			pass := utils.ReadFlagOrDefault(context, "p", "")

			destinationFileName := utils.ReadFlagOrDefault(context, "o", "")
			inputFileName := utils.ReadFlagOrDefault(context, "i", "")
			keyFileName := utils.ReadFlagOrDefault(context, "key", "")

			privateKeyString := ""
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
					privateKeyString = t
					break
				}

			} else {
				privateKeyString = utils.ReadParamOrDefaultOrFromConsole(context, "pr_key", "private key", "")
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
			key, err := SignFunc(privateKeyString, pass, data)

			if err != nil {
				fmt.Println("decryption err")
				return err
			}

			_, err = fmt.Fprintln(writer, string(key))
			if err != nil {
				return err
			}
			return err
		},
	}
}

func SignFunc(privateKeyString, password string, data []byte) (publicKey []byte, err error) {

	fmt.Println(privateKeyString)
	pk, err := cryptoimpl.DecodePrivateKey([]byte(privateKeyString), []byte(password))

	if err != nil {
		return nil, err
	}

	dd, err := base64.StdEncoding.DecodeString(string(data))

	if err != nil {
		fmt.Println("conversion err")
		return nil, err
	}

	return crypto.Sign(dd, pk)
}
