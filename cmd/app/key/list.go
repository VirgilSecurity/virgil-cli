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
	"sort"

	"github.com/pkg/errors"
	"gopkg.in/urfave/cli.v2"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/models"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

func List(vcli *client.VirgilHTTPClient) *cli.Command {
	return &cli.Command{
		Name:    "list",
		Aliases: []string{"l"},
		Usage:   "List your App Keys",
		Flags:   []cli.Flag{&cli.StringFlag{Name: "app_id", Aliases: []string{"app-id"}, Usage: "application id"}},
		Action: func(context *cli.Context) (err error) {
			defaultApp, _ := utils.LoadDefaultApp()
			defaultAppID := ""
			if defaultApp != nil {
				defaultAppID = defaultApp.ID
			}

			appID := utils.ReadFlagOrDefault(context, "app_id", defaultAppID)
			if appID == "" {
				return errors.New("Please, specify app_id (flag --app_id)")
			}

			var keys []*models.AccessKey
			keys, err = listFunc(appID, vcli)

			if err != nil {
				return err
			}

			if len(keys) == 0 {
				fmt.Println("There are no app keys created for application")
				return nil
			}
			sort.Slice(keys, func(i, j int) bool {
				return keys[i].CreatedAt.Before(keys[j].CreatedAt)
			})
			fmt.Printf("|%25s|%35s|%63s |%20s\n", "App key name   ", "App Key ID   ", " PublicKey ", " Created at ")
			fmt.Printf("|%25s|%35s|%64s|%20s\n",
				"-------------------------",
				"-----------------------------------",
				"----------------------------------------------------------------",
				"---------------------------------------",
			)

			for _, k := range keys {
				fmt.Printf("| %23s | %33s | %62s | %20s\n", k.Name, k.ID, base64.StdEncoding.EncodeToString(k.PublicKey), k.CreatedAt)
			}
			return nil
		},
	}
}

func listFunc(appID string, vcli *client.VirgilHTTPClient) (keys []*models.AccessKey, err error) {
	_, _, err = utils.SendWithCheckRetry(vcli, http.MethodGet, "application/"+appID+"/apikeys", nil, &keys)

	if err != nil {
		return
	}

	if keys != nil {
		return keys, nil
	}

	return nil, errors.New("empty response")
}

func getKey(appID string, keyID string, vcli *client.VirgilHTTPClient) (app *models.AccessKey, err error) {
	kk, err := listFunc(appID, vcli)
	if err != nil {
		return
	}

	if len(kk) != 0 {
		for _, k := range kk {
			if k.ID == keyID {
				return k, nil
			}
		}
	}
	return nil, errors.New(fmt.Sprintf("key with id %s not found", keyID))
}
