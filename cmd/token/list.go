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
	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/models"
	"github.com/VirgilSecurity/virgil-cli/utils"
	"github.com/pkg/errors"
	"gopkg.in/urfave/cli.v2"
	"net/http"
	"sort"
)

func List(vcli *client.VirgilHttpClient) *cli.Command {
	return &cli.Command{
		Name:    "list",
		Aliases: []string{"l"},
		Usage:   "List your app tokens",
		Flags:   []cli.Flag{&cli.StringFlag{Name: "app_id", Usage: "app id"}},
		Action: func(context *cli.Context) (err error) {

			defaultApp, err := utils.LoadDefaultApp()
			defaultAppID := ""
			if defaultApp != nil {
				defaultAppID = defaultApp.ID
			}

			appID := utils.ReadFlagOrDefault(context, "app_id", defaultAppID)
			if appID == "" {
				return errors.New("Please, specify app_id (flag --app_id)")
			}

			var tokens []*models.ApplicationToken
			tokens, err = listFunc(appID, vcli)

			if err != nil {
				return err
			}
			if len(tokens) == 0 {
				fmt.Println("There are no tokens created for the application")
				return nil
			}
			sort.Slice(tokens, func(i, j int) bool {
				return tokens[i].CreatedAt.Before(tokens[j].CreatedAt)
			})
			fmt.Printf("|%50s|%20s\n", " Name  ", " Created On ")
			fmt.Printf("|%50s|%20s\n", "--------------------------------------------------", "----------------------------------------")
			for _, t := range tokens {
				fmt.Printf("| %48s |  %18s\n", t.Name, t.CreatedAt)
			}
			return nil
		},
	}
}

func listFunc(appID string, vcli *client.VirgilHttpClient) (apps []*models.ApplicationToken, err error) {

	_, _, err = utils.SendWithCheckRetry(vcli, http.MethodGet, "application/"+appID+"/tokens", nil, &apps)

	if err != nil {
		return
	}

	if apps != nil {
		return apps, nil
	}

	return nil, errors.New("empty response")
}
