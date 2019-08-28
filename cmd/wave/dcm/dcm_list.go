package dcm

import (
	"fmt"
	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/models"
	"github.com/VirgilSecurity/virgil-cli/utils"
	"github.com/pkg/errors"
	"gopkg.in/urfave/cli.v2"
	"net/http"
	"sort"
)

func DcmList(vcli *client.VirgilHttpClient) *cli.Command {
	return &cli.Command{
		Name:    "list",
		Aliases: []string{"l"},
		Usage:   "List your dcm certificates",
		Action: func(context *cli.Context) (err error) {

			defaultApp, err := utils.LoadDefaultApp()
			defaultAppID := ""
			if defaultApp != nil {
				defaultAppID = defaultApp.ID
			}
			appID := utils.ReadFlagOrDefault(context, "app_id", defaultAppID)

			certs, err := dcmListFunc(appID, vcli)
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

func dcmListFunc(appID string, vcli *client.VirgilHttpClient) (apps []*models.DcmCertificateListItem, err error) {

	_, _, err = utils.SendWithCheckRetry(vcli, http.MethodGet, "/scms/"+appID+"/dcm", nil, &apps)

	if err != nil {
		return
	}

	if apps != nil {
		return apps, nil
	}

	return nil, errors.New("empty response")
}

//CMD: virgil wave dcm list
//URL:  https://api.virgilsecurity.com/v1/scms/{APPLICATION_ID}/dcm
//METHOD: GET
//RESP BODY: [
//    {"name": "My first DCM certificate", "created_at": "2005-08-09T18:31:42-03"}
//]
