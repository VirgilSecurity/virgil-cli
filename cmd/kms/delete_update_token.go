package kms

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/golang/protobuf/proto"
	"github.com/urfave/cli/v2"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/cmd/kms/protobuf/decryptor"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

func DeleteUpdateToken(vcli *client.VirgilHTTPClient) *cli.Command {
	return &cli.Command{
		Name:      "delete-update-token",
		Aliases:   []string{"dut"},
		ArgsUsage: "kms_key_alias",
		Usage:     "Delete KMS update token",
		Action: func(context *cli.Context) (err error) {
			aliasKMSKey := context.Args().First()

			defaultApp, _ := utils.LoadDefaultApp()
			defaultAppToken := ""
			if defaultApp != nil {
				defaultAppToken = defaultApp.Token
			}

			appToken := utils.ReadFlagOrDefault(context, "app-token", defaultAppToken)
			if appToken == "" {
				return errors.New("please, specify app-token (flag --app-token)")
			}

			if err := deleteUpdateToken(appToken, aliasKMSKey, vcli); err != nil {
				return err
			}
			return nil
		},
	}
}

func deleteUpdateToken(appToken string, keyAlias string, vcli *client.VirgilHTTPClient) (err error) {
	reqPayload, err := proto.Marshal(&decryptor.KeypairRequest{Alias: keyAlias})
	if err != nil {
		return err
	}

	_, _, err = utils.SendProtoWithCheckRetry(vcli, http.MethodPost, "kms/v1/delete-update-token", reqPayload, nil, appToken)

	if err != nil {
		return err
	}

	fmt.Println("Update token successfully deleted.")
	return nil
}
