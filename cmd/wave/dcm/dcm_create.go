package dcm

import (
	"encoding/json"
	"fmt"
	"github.com/VirgilSecurity/virgil-cli/utils"
	"net/http"

	"github.com/VirgilSecurity/virgil-cli/models"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/pkg/errors"
	"gopkg.in/urfave/cli.v2"
)

func DsmCreate(vcli *client.VirgilHttpClient) *cli.Command {
	return &cli.Command{
		Name:    "create",
		Aliases: []string{"c"},
		Usage:   "Create new dcm certificate",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "name", Usage: "dsm certificate name"},
			&cli.StringFlag{Name: "app_id", Aliases: []string{"app-id"}, Usage: "application id"},
			&cli.StringFlag{Name: "encrypt-pub-key", Usage: "encrypt public key"},
			&cli.StringFlag{Name: "app-token", Usage: "application token"},
			&cli.StringFlag{Name: "verify-pub-key", Usage: "verify public key"}},

		Action: func(context *cli.Context) (err error) {

			name := utils.ReadFlagOrConsoleValue(context, "name", "Enter dsm certificate name")
			encryptPubKey := utils.ReadFlagOrConsoleValue(context, "encrypt-pub-key", "Enter encrypt public key")
			verifyPubKey := utils.ReadFlagOrConsoleValue(context, "verify-pub-key", "Enter verify public key")

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
			dcm, err := DsmCreateFunc(appID, name, encryptPubKey, verifyPubKey, appToken, vcli)
			if err != nil {
				return err
			}
			serialized, err := json.MarshalIndent(dcm,"","\t")
			if err != nil {
				return err
			}
			fmt.Println(string(serialized))

			return
		},
	}
}

func DsmCreateFunc(appID, name, encryptPubKey, verifyPubKey, appToken string, vcli *client.VirgilHttpClient) (resp models.DcmCertificateCreateResponse, err error) {

	req := &models.DcmCertificateCreateRequest{Name: name, EncryptPublicKey: encryptPubKey, VerifyPublicKey: verifyPubKey}

	_, _, err = utils.SendWithCheckRetry(vcli, http.MethodPost, "/scms/"+appID+"/dcm", req, &resp, appToken)
	return
}

//CMD: virgil wave dcm create  --name "My first DCM certificate" --encrypt-pub-key BASE64 --verfiy-pub-key BASE64
//URL    :  https://api.virgilsecurity.com/v1/scms/{APPLICATION_ID}/dcm
//METHOD: POST
//BODY: {"name":"My first DCM certificate","encrypt_public_key":"BASE64","verify_public_key":"BASE64"}
//RESP BODY: {
//    "name": "human name for DCM certificate",
//    "certificate": "BASE64",
//    "eca_address": "https://api.virgilsecurity.com/scms/v1",
//    "eca_certificate": "BASE64",
//    "ra_address": "https://api.virgilsecurity.com/scms/v1",
//    "lccf": "BASE64",
//}
