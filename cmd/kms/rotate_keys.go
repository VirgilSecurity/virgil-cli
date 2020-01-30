package kms

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto/wrapper/phe"
	"github.com/urfave/cli/v2"
)

var keyPrefixes = []string{"KS.", "KP."}

// RotateKeys updates Client Private key and Server Public key using Update token
func RotateKeys() *cli.Command {
	return &cli.Command{
		Name:      "rotate",
		Aliases:   []string{"r"},
		ArgsUsage: "client_private_key server_public_key update_token",
		Usage:     "rotate KMS Recovery Password Key",
		Action:    rotateKMSKeys,
	}
}

func rotateKMSKeys(context *cli.Context) (err error) {
	b64ClientPrivateKey := context.Args().First()
	b64ServerPublicKey := context.Args().Get(1)
	b64UpdateToken := context.Args().Get(2)

	trimPrefix(&b64ClientPrivateKey)
	prefixedServerPublicKey := trimPrefix(&b64ServerPublicKey)

	clientPrivateKey, err := base64.StdEncoding.DecodeString(b64ClientPrivateKey)
	if err != nil {
		return err
	}

	serverPublicKey, err := base64.StdEncoding.DecodeString(b64ServerPublicKey)
	if err != nil {
		return err
	}

	updateToken, err := base64.StdEncoding.DecodeString(b64UpdateToken)
	if err != nil {
		return err
	}

	kmsClient := phe.NewUokmsClient()
	if err = kmsClient.SetKeys(clientPrivateKey, serverPublicKey); err != nil {
		return err
	}
	if err = kmsClient.SetupDefaults(); err != nil {
		return err
	}

	newClientPrivateKey, newServerPublicKey, err := kmsClient.RotateKeys(updateToken)
	if err != nil {
		return err
	}

	var n64NewServerPublicKey string
	if prefixedServerPublicKey {
		n64NewServerPublicKey = RecoveryPasswordKeyPrefix + base64.StdEncoding.EncodeToString(newServerPublicKey)
	} else {
		n64NewServerPublicKey = base64.StdEncoding.EncodeToString(newServerPublicKey)
	}

	fmt.Printf(
		"New server public key:\n%s\nNew client private key:\nKS.%s\n",
		n64NewServerPublicKey,
		base64.StdEncoding.EncodeToString(newClientPrivateKey),
	)
	return nil
}

func trimPrefix(prefixedString *string) bool {
	for _, prefix := range keyPrefixes {
		if strings.HasPrefix(*prefixedString, prefix) {
			*prefixedString = strings.TrimPrefix(*prefixedString, prefix)
			return true
		}
	}
	return false
}
