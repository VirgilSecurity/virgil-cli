package kms

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/cmd/kms/protobuf/decryptor"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

func GetUpdateToken(vcli *client.VirgilHTTPClient) *cli.Command {
	return &cli.Command{
		Name:      "get-update-token",
		Aliases:   []string{"ut"},
		ArgsUsage: "kms_key_alias",
		Usage:     "Get KMS update token",
		Action: func(context *cli.Context) (err error) {
			aliasKMSKey := context.Args().First()

			defaultApp, _ := utils.LoadDefaultApp()
			defaultAppToken := ""
			if defaultApp != nil {
				defaultAppToken = defaultApp.Token
			}

			appToken := utils.ReadFlagOrDefault(context, "app-token", defaultAppToken)
			if appToken == "" {
				return errors.New("Please, specify app-token (flag --app-token)")
			}

			if err := printUpdateToken(appToken, aliasKMSKey, vcli); err != nil {
				return err
			}
			return nil
		},
	}
}

func printUpdateToken(appToken string, keyAlias string, vcli *client.VirgilHTTPClient) (err error) {
	reqPayload, err := proto.Marshal(&decryptor.KeypairRequest{Alias: keyAlias})
	if err != nil {
		return err
	}

	var resp []byte

	_, _, err = utils.SendProtoWithCheckRetry(vcli, http.MethodPost, "kms/v1/create-update-token", reqPayload, &resp, appToken)
	if err != nil {
		return err
	}

	protoUpdateToken := &decryptor.UpdateTokenResponse{}
	if err := proto.Unmarshal(resp, protoUpdateToken); err != nil {
		return err
	}

	fmt.Println(base64.StdEncoding.EncodeToString(protoUpdateToken.UpdateToken))

	return nil
}
