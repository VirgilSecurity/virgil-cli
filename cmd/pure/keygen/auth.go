package keygen

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/urfave/cli/v2"
)

// Auth generates Auth key
func Auth() *cli.Command {
	return &cli.Command{
		Name:    "auth",
		Aliases: []string{"ak"},
		Usage:   "Generate a new Auth key",
		Action: func(context *cli.Context) error {
			return printAuthKey()
		},
	}
}

func printAuthKey() error {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return err
	}
	fmt.Println("AK." + base64.StdEncoding.EncodeToString(key))
	return nil
}
