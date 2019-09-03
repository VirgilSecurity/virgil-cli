package device

import (
	"fmt"
	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/models"
	"github.com/VirgilSecurity/virgil-cli/utils"
	"github.com/pkg/errors"
	"gopkg.in/urfave/cli.v2"
	"net/http"
)

func DeviceList(vcli *client.VirgilHttpClient) *cli.Command {
	return &cli.Command{
		Name:    "list",
		Aliases: []string{"l"},
		Usage:   "List your devices",
		Flags:   []cli.Flag{
			&cli.StringFlag{Name: "app_id", Aliases:[]string{"app-id"},Usage: "application id"},
			&cli.StringFlag{Name: "app-token", Usage: "application token"}},
		Action: func(context *cli.Context) (err error) {

			defaultApp, err := utils.LoadDefaultApp()
			defaultAppID := ""
			defaultAppToken := ""
			if defaultApp != nil {
				defaultAppID = defaultApp.ID
				defaultAppToken = defaultApp.Token
			}
			appID := utils.ReadFlagOrDefault(context, "app_id", defaultAppID)
			if appID == "" {
				return errors.New("Please, specify app_id (flag --app_id)")
			}
			appToken := utils.ReadFlagOrDefault(context, "app-token", defaultAppToken)
			if appToken == "" {
				return errors.New("Please, specify app-token (flag --app-token)")
			}

			devices, err := deviceListFunc(appID, appToken, vcli)
			if err != nil {
				return err
			}

			if len(devices) == 0 {
				fmt.Println("There are no devices rgistered for the application")
				return nil
			}

			fmt.Printf("|%25s|%35s|%20s|%20s\n", "Device id    ", "dcm id   ", " valid_from ", " valid_to ")
			fmt.Printf("|%25s|%35s|%20s|%20s\n", "-------------------------", "-----------------------------------", "---------------------------------------", "---------------------------------------")
			for _, d := range devices {
				fmt.Printf("|%25s|%35s| %19s | %19s\n", d.ID, d.DcmID, d.ValidFrom, d.ValidTo)
			}
			return nil
		},
	}
}

func deviceListFunc(appID, appToken string, vcli *client.VirgilHttpClient) (devices []*models.Device, err error) {

	_, _, err = utils.SendWithCheckRetry(vcli, http.MethodGet, "scms/"+appID+"/devices", nil, &devices, appToken)

	if err != nil {
		return
	}

	if devices != nil {
		return devices, nil
	}

	return nil, errors.New("empty response")
}

//CMD: virgil wave device list
//URL: https://api.virgilsecurity.com/v1/scms/{APPLICATION_ID}/devices
//METHOD: GET
//RESP BODY: [
//    {"id": "HEX", "dcm_id": "HEX", "valid_from": "2005-08-09T18:31:42-03", "valid_to": "2005-08-09T18:31:42-03"}
//]
