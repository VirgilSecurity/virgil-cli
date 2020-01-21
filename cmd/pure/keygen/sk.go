package keygen

import (
	"encoding/base64"
	"fmt"

	phe "github.com/VirgilSecurity/virgil-phe-go"
	"github.com/urfave/cli/v2"
)

// Secret generates secret key
func Secret() *cli.Command {
	return &cli.Command{
		Name:    "secret",
		Aliases: []string{"sk"},
		Usage:   "Generate a new Secret key",
		Action: func(context *cli.Context) error {
			return printSecretKey()
		},
	}
}

func printSecretKey() error {
	key := phe.GenerateClientKey()
	fmt.Println("SK.1." + base64.StdEncoding.EncodeToString(key))
	return nil
}