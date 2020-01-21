package keygen

import (
	"fmt"

	"github.com/urfave/cli/v2"
)

// All generates all pure key pairs
func All() *cli.Command {
	return &cli.Command{
		Name:  "all",
		Usage: "Generates all pure key pairs",
		Action: func(context *cli.Context) error {
			fmt.Println("----------------------------------------------------------------------------------")
			if err := printAuthKey(); err != nil {
				return err
			}

			fmt.Println("==================================================================================")

			if err := printBackupKey(); err != nil {
				return err
			}

			fmt.Println("==================================================================================")

			if err := printHBKey(); err != nil {
				return err
			}

			fmt.Println("==================================================================================")

			if err := printSecretKey(); err != nil {
				return err
			}

			fmt.Println("==================================================================================")

			if err := printSigningKey(); err != nil {
				return err
			}

			fmt.Println("==================================================================================")

			if err := printOwnSigningKey(); err != nil {
				return err
			}
			fmt.Println("----------------------------------------------------------------------------------")

			return nil
		},
	}
}
