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

package app

import (
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
		Usage:   "List your apps",
		Action: func(context *cli.Context) (err error) {
			var apps []*models.Application
			apps, err = listFunc(vcli)

			if err != nil {
				return err
			}

			defaultApp, _ := utils.LoadDefaultApp()
			defaultAppID := ""
			if defaultApp != nil {
				defaultAppID = defaultApp.ID
			}
			if len(apps) == 0 {
				fmt.Println("There are no applications created for the account")
				return nil
			}
			sort.Slice(apps, func(i, j int) bool {
				return apps[i].CreatedAt.Before(apps[j].CreatedAt)
			})
			fmt.Printf("|%25s|%35s|%20s\n", "Application name   ", "APP_ID   ", " created_at ")
			fmt.Printf("|%25s|%35s|%20s\n",
				"-------------------------",
				"-----------------------------------",
				"---------------------------------------",
			)
			for _, app := range apps {
				appName := app.Name
				if app.ID == defaultAppID {
					appName += " (default)"
				}
				fmt.Printf("| %23s | %33s | %19s\n", appName, app.ID, app.CreatedAt)
			}
			return nil
		},
	}
}

func listFunc(vcli *client.VirgilHTTPClient) (apps []*models.Application, err error) {
	_, _, err = utils.SendWithCheckRetry(vcli, http.MethodGet, "applications", nil, &apps)

	if err != nil {
		return
	}

	if apps != nil {
		return apps, nil
	}

	return nil, errors.New("empty response")
}
