package scms

import (
	"errors"
	"fmt"
	"net/http"

	"gopkg.in/urfave/cli.v2"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

func Init(vcli *client.VirgilHTTPClient) *cli.Command {
	return &cli.Command{
		Name:  "init",
		Usage: "Init scms module in application",
		Flags: []cli.Flag{&cli.StringFlag{Name: "app_id", Aliases: []string{"app-id"}, Usage: "application id"}},

		Action: func(context *cli.Context) (err error) {
			defaultApp, _ := utils.LoadDefaultApp()
			defaultAppID := ""
			if defaultApp != nil {
				defaultAppID = defaultApp.ID
			}
			appID := utils.ReadFlagOrDefault(context, "app_id", defaultAppID)
			if appID == "" {
				return errors.New("please, specify app-id (flag --app-id)")
			}

			err = InitFunc(appID, vcli)

			if err != nil {
				return err
			}

			fmt.Println("Application init ok.")
			return nil
		},
	}
}

func InitFunc(appID string, vcli *client.VirgilHTTPClient) (err error) {
	_, _, err = utils.SendWithCheckRetry(vcli, http.MethodPost, "scms/"+appID+"/init", nil, nil)
	return err
}

//CMD: virgil scms  init
//URL: https://api.virgilsecurity.com/management/v1/scms/{APPLICATION_ID}/init
//METHOD: POST
