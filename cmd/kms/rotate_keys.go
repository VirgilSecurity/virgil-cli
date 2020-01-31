package kms

import (
	"encoding/base64"
	"errors"
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
		Action:    rotateKMSKeysCommand,
	}
}

func rotateKMSKeysCommand(context *cli.Context) (err error) {
	if context.NArg() < 3 {
		return errors.New("invalid number of arguments")
	}

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

	newClientPrivateKey, newServerPublicKey, err := RotateKMSKeys(clientPrivateKey, serverPublicKey, updateToken)
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

func RotateKMSKeys(kmsPrivateKey, kmsPublicKey, updateToken []byte) (newKMSPrivateKey, newKMSPublicKey []byte, err error) {
	kmsClient := phe.NewUokmsClient()
	if err = kmsClient.SetKeys(kmsPrivateKey, kmsPublicKey); err != nil {
		return nil, nil, err
	}
	if err = kmsClient.SetupDefaults(); err != nil {
		return nil, nil, err
	}

	newKMSPrivateKey, newKMSPublicKey, err = kmsClient.RotateKeys(updateToken)
	if err != nil {
		return nil, nil, err
	}
	return
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
