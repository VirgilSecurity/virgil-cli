/*
 * Copyright (C) 2015-2019 Virgil Security Inc.
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

package key

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/models"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

var crypt = &crypto.Crypto{}

func Create(vcli *client.VirgilHTTPClient) *cli.Command {
	return &cli.Command{
		Name:      "create",
		Aliases:   []string{"c"},
		ArgsUsage: "app-key name",
		Usage:     "Create a new App Key",
		Flags:     []cli.Flag{&cli.StringFlag{Name: "app_id", Aliases: []string{"app-id"}, Usage: "application id"}},
		Action: func(context *cli.Context) (err error) {
			defaultApp, _ := utils.LoadDefaultApp()
			defaultAppID := ""
			if defaultApp != nil {
				defaultAppID = defaultApp.ID
			}

			appID := utils.ReadFlagOrDefault(context, "app_id", defaultAppID)
			if appID == "" {
				return utils.CliExit(errors.New(utils.SpecifyAppIDFlag))
			}

			name := utils.ReadParamOrDefaultOrFromConsole(context, "name", utils.AppKeyNamePrompt, "")

			_, err = getApp(appID, vcli)
			if err != nil {
				return utils.CliExit(err)
			}

			var apiKeyID string
			apiKeyID, err = CreateFunc(name, appID, vcli)

			if err != nil {
				return utils.CliExit(err)
			}

			fmt.Println("App Key ID:", apiKeyID)
			return nil
		},
	}
}

func CreateFunc(name, appID string, vcli *client.VirgilHTTPClient) (apiKeyID string, err error) {
	keyPair, err := crypt.GenerateKeypair()

	if err != nil {
		return "", err
	}

	prKey, err := crypt.ExportPrivateKey(keyPair)
	if err != nil {
		return "", err
	}
	pubKey, err := crypt.ExportPublicKey(keyPair.PublicKey())
	if err != nil {
		return "", err
	}
	sign, err := crypt.Sign(pubKey, keyPair)
	if err != nil {
		return "", err
	}
	req := &models.CreateAccessKeyRequest{Name: name, PublicKey: pubKey, Signature: sign}
	resp := &models.AccessKey{}

	_, _, err = utils.SendWithCheckRetry(vcli, http.MethodPost, "application/"+appID+"/apikey", req, resp)

	if err != nil {
		return
	}

	if resp != nil {
		fmt.Println(utils.AppKeyCreateWarning)
		fmt.Println(utils.AppKeyCreateSuccess)
		fmt.Println(utils.AppKeyOutput, base64.StdEncoding.EncodeToString(prKey))

		return resp.ID, nil
	}

	return "", errors.New("empty response")
}

func getApp(appID string, vcli *client.VirgilHTTPClient) (app *models.Application, err error) {
	var apps []*models.Application
	_, _, err = utils.SendWithCheckRetry(vcli, http.MethodGet, "applications", nil, &apps)

	if err != nil {
		return
	}

	if len(apps) != 0 {
		for _, a := range apps {
			if a.ID == appID {
				return a, nil
			}
		}
		return nil, errors.New(fmt.Sprintf("%s %s \n", utils.ApplicationNotFound, appID))
	}

	return nil, errors.New("empty response")
}
