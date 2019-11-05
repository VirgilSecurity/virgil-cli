package device

import (
	"fmt"
	"net/http"

	"github.com/pkg/errors"
	"gopkg.in/urfave/cli.v2"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/models"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

func List(vcli *client.VirgilHTTPClient) *cli.Command {
	return &cli.Command{
		Name:    "list",
		Aliases: []string{"l"},
		Usage:   "List your devices",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "app-token", Usage: "application token"}},
		Action: func(context *cli.Context) (err error) {

			defaultApp, _ := utils.LoadDefaultApp()
			defaultAppToken := ""
			if defaultApp != nil {
				defaultAppToken = defaultApp.Token
			}
			appToken := utils.ReadFlagOrDefault(context, "app-token", defaultAppToken)
			if appToken == "" {
				return errors.New("Please, specify app-token (flag --app-token)")
			}

			devices, err := deviceListFunc(appToken, vcli)
			if err != nil {
				return err
			}

			if len(devices) == 0 {
				fmt.Println("There are no devices rgistered for the application")
				return nil
			}

			fmt.Printf("|%25s|%35s|%20s|%20s\n", "Device id    ", "dcm id   ", " valid_from ", " valid_to ")
			fmt.Printf("|%25s|%35s|%20s|%20s\n",
				"-------------------------",
				"-----------------------------------",
				"---------------------------------------",
				"---------------------------------------",
			)
			for _, d := range devices {
				fmt.Printf("|%25s|%35s| %19s | %19s\n", d.ID, d.DcmID, d.ValidFrom, d.ValidTo)
			}
			return nil
		},
	}
}

func deviceListFunc(appToken string, vcli *client.VirgilHTTPClient) (devices []*models.Device, err error) {

	_, _, err = utils.SendWithCheckRetry(vcli, http.MethodGet, "scms/devices", nil, &devices, appToken)

	if err != nil {
		return
	}

	if devices != nil {
		return devices, nil
	}

	return nil, errors.New("empty response")
}

//CMD: virgil scms device list
//URL: https://api.virgilsecurity.com/v1/scms/{APPLICATION_ID}/devices
//METHOD: GET
//RESP BODY: [
//    {"id": "HEX", "dcm_id": "HEX", "valid_from": "2005-08-09T18:31:42-03", "valid_to": "2005-08-09T18:31:42-03"}
//]
