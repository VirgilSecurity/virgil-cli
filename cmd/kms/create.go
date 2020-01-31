package kms

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/golang/protobuf/proto"
	"github.com/urfave/cli/v2"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/cmd/kms/protobuf/decryptor"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

const (
	RecoveryPasswordAlias     = "RECOVERY_PASSWORD"
	RecoveryPasswordKeyPrefix = "KP."
	PrefixKMSApi              = "kms/v1"
)

// Create KMS Public key
func Create(vcli *client.VirgilHTTPClient) *cli.Command {
	return &cli.Command{
		Name:      "create",
		Aliases:   []string{"c"},
		ArgsUsage: "key_name",
		Usage:     "Create a new key",

		Action: func(context *cli.Context) (err error) {
			name := utils.ReadParamOrDefaultOrFromConsole(context, "name", "Enter key name", "")

			defaultApp, _ := utils.LoadDefaultApp()
			defaultAppToken := ""
			if defaultApp != nil {
				defaultAppToken = defaultApp.Token
			}

			appToken := utils.ReadFlagOrDefault(context, "app-token", defaultAppToken)
			if appToken == "" {
				return errors.New("please, specify app-token (flag --app-token)")
			}

			keyPair, err := CreateFunc(name, appToken, vcli)

			if err != nil {
				return err
			}

			fmt.Printf(
				"KMS Key alias: %s version: %d public key: %s\n",
				keyPair.Alias,
				int(keyPair.KeyVersion),
				recoveryKeyChecker(keyPair),
			)
			fmt.Println("KMS Key Pair has been successfully created.")
			return nil
		},
	}
}

func CreateFunc(name, appToken string, vcli *client.VirgilHTTPClient) (keyPair *decryptor.Keypair, err error) {
	reqPayload, err := proto.Marshal(&decryptor.KeypairRequest{Alias: name})
	if err != nil {
		return nil, err
	}
	var rawResp []byte
	_, _, err = utils.SendProtoWithCheckRetry(vcli, http.MethodPost, PrefixKMSApi+"/keypair", reqPayload, &rawResp, appToken)

	if err != nil {
		return nil, err
	}

	if len(rawResp) == 0 {
		return nil, errors.New("raw response lengths = 0")
	}

	keyPair = &decryptor.Keypair{}
	if err := proto.Unmarshal(rawResp, keyPair); err != nil {
		return nil, err
	}

	return keyPair, nil
}

func recoveryKeyChecker(keyPair *decryptor.Keypair) string {
	if keyPair.Alias == RecoveryPasswordAlias {
		return RecoveryPasswordKeyPrefix + base64.StdEncoding.EncodeToString(keyPair.PublicKey)
	}
	return base64.StdEncoding.EncodeToString(keyPair.PublicKey)
}
