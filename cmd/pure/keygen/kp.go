package keygen

import (
	"encoding/base64"
	"fmt"

	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto/wrapper/phe"
	"github.com/urfave/cli/v2"
)

//
// KMSPrivateKey generates KMS Private Key
//
func KMSPrivateKey() *cli.Command {
	return &cli.Command{
		Name:    "kms-client-private",
		Aliases: []string{"pk"},
		Usage:   "Generate a new KMS Client Private key",
		Action: func(context *cli.Context) error {
			return printKMSPrivateKey()
		},
	}
}

func printKMSPrivateKey() error {
	kmsClient := phe.NewUokmsClient()
	if err := kmsClient.SetupDefaults(); err != nil {
		return err
	}

	key, err := kmsClient.GenerateClientPrivateKey()
	if err != nil {
		return err
	}
	fmt.Println("KS." + base64.StdEncoding.EncodeToString(key))
	return nil
}
