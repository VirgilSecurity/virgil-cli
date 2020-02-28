/*
 * Copyright (C) 2015-2020 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */
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
		Flags:     []cli.Flag{&cli.StringFlag{Name: "app-token", Usage: "application token"}},

		Action: func(context *cli.Context) (err error) {
			name := utils.ReadParamOrDefaultOrFromConsole(context, "name", utils.KMSKeyNamePrompt, "")

			defaultApp, _ := utils.LoadDefaultApp()
			defaultAppToken := ""
			if defaultApp != nil {
				defaultAppToken = defaultApp.Token
			}

			appToken := utils.ReadFlagOrDefault(context, "app-token", defaultAppToken)
			if appToken == "" {
				return utils.CliExit(errors.New(utils.SpecifyAppTokenFlag))
			}

			keyPair, err := CreateFunc(name, appToken, vcli)

			if err != nil {
				return utils.CliExit(err)
			}

			fmt.Printf(
				"KMS Key alias: %s version: %d public key: %s\n",
				keyPair.Alias,
				int(keyPair.KeyVersion),
				recoveryKeyChecker(keyPair),
			)
			fmt.Println(utils.KMSKeyCreateSuccess)
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
