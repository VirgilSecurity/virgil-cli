package cards

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/urfave/cli.v2"
	"gopkg.in/virgil.v5/sdk"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

func Revoke(vcli *client.VirgilHTTPClient) *cli.Command {
	return &cli.Command{
		Name:      "revoke",
		ArgsUsage: "[id]",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "c", Usage: "private key password"},
			&cli.StringFlag{Name: "i", Usage: "config file name"},
		},
		Usage: "delete cards by id",
		Action: func(context *cli.Context) error {

			cardID := utils.ReadParamOrDefaultOrFromConsole(context, "id", "Enter card id", "")

			configFileName := utils.ReadFlagOrDefault(context, "c", "")
			if configFileName == "" {
				return errors.New("configuration file isn't specified (use -c)")
			}

			identity := utils.ReadFlagOrConsoleValue(context, "i", "Enter card identity")

			data, err := ioutil.ReadFile(configFileName)
			if err != nil {
				fmt.Print(err)
			}

			conf, err := utils.ParseAppConfig(data)
			if err != nil {
				fmt.Print(err)
			}

			privateKey, err := crypto.ImportPrivateKey(conf.APIKey, "")
			if err != nil {
				return err
			}

			ttl := time.Minute

			jwtGenerator := sdk.NewJwtGenerator(privateKey, conf.APIKeyID, tokenSigner, conf.AppID, ttl)

			yesOrNo := utils.ReadConsoleValue("y or n", fmt.Sprintf("Are you sure, that you want to delete card (y/n) ?"), "y", "n")
			if yesOrNo == "n" {
				return nil
			}
			token, err := jwtGenerator.GenerateToken(identity, nil)
			if err != nil {
				return err
			}
			err = deleteCardFunc(cardID, token.String(), vcli)
			if err != nil {
				return err
			}
			if err == nil {
				fmt.Println("Card delete ok.")
			} else if err == utils.ErrEntityNotFound {
				return errors.New(fmt.Sprintf("card with id %s not found.\n", cardID))
			}

			return nil
		},
	}
}

func deleteCardFunc(cardID, authorization string, vcli *client.VirgilHTTPClient) (err error) {

	_, _, err = utils.SendWithCheckRetry(vcli, http.MethodPost, "card/v5/actions/revoke/"+cardID, nil, nil, authorization)
	return err
}
