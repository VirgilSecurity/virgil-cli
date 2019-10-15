package keygen

import (
	"encoding/base64"
	"fmt"

	"github.com/VirgilSecurity/virgil-phe-go"
	"gopkg.in/urfave/cli.v2"
)

//Keygen generates Auth key
func Auth() *cli.Command {
	return &cli.Command{
		Name:    "auth",
		Aliases: []string{"ak"},
		Usage:   "Generate a new Auth key",
		Action: func(context *cli.Context) error {
			key := phe.GenerateClientKey()
			fmt.Println("AK." + base64.StdEncoding.EncodeToString(key))
			return nil
		},
	}
}
