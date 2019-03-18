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

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/models"
	"github.com/VirgilSecurity/virgil-cli/utils"
	"github.com/pkg/errors"
	"gopkg.in/urfave/cli.v2"
)

func List(vcli *client.VirgilHttpClient) *cli.Command {
	return &cli.Command{
		Name:    "list",
		Aliases: []string{"l"},
		Usage:   "Lists your api-keys",
		Flags:   []cli.Flag{&cli.StringFlag{Name: "app_id"}},
		Action: func(context *cli.Context) (err error) {

			appID := context.String("app_id")
			if appID == "" {
				appID, _ := utils.LoadAppID()
				if appID == "" {
					return errors.New("Please, specify app_id (flag --app_id)")
				}
			} else {
				utils.SaveAppID(appID)
			}

			var keys []*models.AccessKey
			keys, err = listFunc(vcli)

			if err != nil {
				return err
			}

			if len(keys) == 0 {
				fmt.Println("There is no api keys for application")
			}

			for _, k := range keys {
				fmt.Printf("=====  %s  =====\n", k.Name)
				fmt.Printf(" API_KEY_ID : %s \n", k.ID)
				fmt.Printf(" PublicKey : %s \n", base64.StdEncoding.EncodeToString(k.PublicKey))
			}
			return nil
		},
	}
}

func listFunc(vcli *client.VirgilHttpClient) (keys []*models.AccessKey, err error) {

	token, err := utils.LoadAccessTokenOrLogin(vcli)

	if err != nil {
		return keys, err
	}

	for err == nil {
		_, _, vErr := vcli.Send(http.MethodGet, token, "access_keys", nil, &keys)
		if vErr == nil {
			break
		}

		token, err = utils.CheckRetry(vErr, vcli)
	}

	if err != nil {
		return
	}

	if keys != nil {
		return keys, nil
	}

	return nil, errors.New("empty response")
}
