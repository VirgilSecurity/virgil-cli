package keygen

import (
	"fmt"

	"gopkg.in/urfave/cli.v2"
)

//Generates all pure key pairs
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

			if err := PrintSigningKey(); err != nil {
				return err
			}
			fmt.Println("----------------------------------------------------------------------------------")

			return nil
		},
	}
}
