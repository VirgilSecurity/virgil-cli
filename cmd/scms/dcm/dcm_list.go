package dcm

import (
	"fmt"
	"net/http"
	"sort"

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
		Usage:   "List your dcm certificates",
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
				return errors.New("Please, specify app-token (flag --app_token)")
			}

			certs, err := dcmListFunc(appToken, vcli)
			if err != nil {
				return err
			}

			if len(certs) == 0 {
				fmt.Println("There are no certs created for the application")
				return nil
			}
			sort.Slice(certs, func(i, j int) bool {
				return certs[i].CreatedAt.Before(certs[j].CreatedAt)
			})
			fmt.Printf("|%25s|%20s\n", "Certificate name   ", " created_at ")
			fmt.Printf("|%25s|%20s\n", "-------------------------", "---------------------------------------")
			for _, cert := range certs {

				fmt.Printf("|%24s | %19s\n", cert.Name, cert.CreatedAt)
			}
			return nil
		},
	}
}

func dcmListFunc(appToken string, vcli *client.VirgilHTTPClient) (apps []*models.DcmCertificateListItem, err error) {

	_, _, err = utils.SendWithCheckRetry(vcli, http.MethodGet, "/scms/dcm", nil, &apps, appToken)

	if err != nil {
		return
	}

	if apps != nil {
		return apps, nil
	}

	return nil, errors.New("empty response")
}

//CMD: virgil scms dcm list
//URL:  https://api.virgilsecurity.com/v1/scms/{APPLICATION_ID}/dcm
//METHOD: GET
//RESP BODY: [
//    {"name": "My first DCM certificate", "created_at": "2005-08-09T18:31:42-03"}
//]
