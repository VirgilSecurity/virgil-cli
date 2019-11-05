package keygen

import (
	"fmt"

	"gopkg.in/urfave/cli.v2"
)

// All generates all pure key pairs
func All() *cli.Command {
	return &cli.Command{
		Name:  "all",
		Usage: "Generates all pure key pairs",
		Action: func(context *cli.Context) error {
			fmt.Println("----------------------------------------------------------------------------------")
			if err := PrintAuthKey(); err != nil {
				return err
			}

			fmt.Println("==================================================================================")

			if err := PrintBackupKey(); err != nil {
				return err
			}

			fmt.Println("==================================================================================")

			if err := PrintHBKey(); err != nil {
				return err
			}

			fmt.Println("==================================================================================")

			if err := PrintSecretKey(); err != nil {
				return err
			}

			fmt.Println("==================================================================================")

			if err := PrintSigningKey(); err != nil {
				return err
			}
			fmt.Println("----------------------------------------------------------------------------------")

			return nil
		},
	}
}
