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

package token

import (
	"fmt"
	"github.com/VirgilSecurity/virgil-cli/models"
	"net/http"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/utils"
	"github.com/pkg/errors"
	"gopkg.in/urfave/cli.v2"
)

func Delete(vcli *client.VirgilHttpClient) *cli.Command {
	return &cli.Command{
		Name:      "delete",
		Aliases:   []string{"d"},
		ArgsUsage: "name",
		Usage:     "Delete app token by name",
		Flags:     []cli.Flag{&cli.StringFlag{Name: "app_id", Usage: "app id"}},
		Action: func(context *cli.Context) (err error) {

			defaultApp, _ := utils.LoadDefaultApp()
			defaultAppID := ""
			if defaultApp != nil {
				defaultAppID = defaultApp.ID
			}
			name := utils.ReadParamOrDefaultOrFromConsole(context, "name", "Enter token name", "")

			appID := utils.ReadFlagOrDefault(context, "app_id", defaultAppID)
			if appID == "" {
				return errors.New("Please, specify app_id (flag --app_id)")
			}

			var tokens []*models.ApplicationToken
			tokens, err = listFunc(appID, vcli)

			if err != nil {
				return err
			}
			for _, t := range tokens {

				if t.Name == name {
					err = deleteAppTokenFunc(appID, t.ID, vcli)
					if err == nil {
						fmt.Println("delete ok.")
					}
					return err
				}

			}
			fmt.Println("token not found")
			return err
		},
	}
}

func deleteAppTokenFunc(appID, appTokenID string, vcli *client.VirgilHttpClient) (err error) {

	_, _, err = utils.SendWithCheckRetry(vcli, http.MethodDelete, "applications/"+appID+"/tokens/"+appTokenID, nil, nil)
	return err
}
