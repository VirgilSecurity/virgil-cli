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

package cmd

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"gopkg.in/urfave/cli.v2"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/models"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

func UseApp(client *client.VirgilHTTPClient) *cli.Command {
	return &cli.Command{
		Name:      "use",
		Aliases:   []string{"use-default-app"},
		ArgsUsage: "name",
		Usage:     "Changes context to app with specified name. All future commands without specifying app_id will be applied to current app",
		Action: func(context *cli.Context) error {
			return useFunc(context, client)
		},
	}
}

func useFunc(context *cli.Context, vcli *client.VirgilHTTPClient) error {

	if context.NArg() < 1 {
		return errors.New("Invalid number of arguments. Please, specify application name")
	}

	appName := strings.Join(context.Args().Slice(), " ")

	var apps []*models.Application
	apps, err := listFunc(vcli)

	if err != nil {
		return err
	}

	for _, app := range apps {
		if app.Name == appName {
			err := utils.SaveDefaultApp(vcli, app)
			if err != nil {
				return err
			}
			fmt.Println("Application context set ok")
			fmt.Println("All future commands without specifying app_id will be applied to current app")
			return nil
		}
	}

	return errors.New("there is no app with name " + appName)
}

func listFunc(vcli *client.VirgilHTTPClient) (apps []*models.Application, err error) {

	_, _, err = utils.SendWithCheckRetry(vcli, http.MethodGet, "applications", nil, &apps)

	if err != nil {
		return apps, err
	}

	if apps != nil {
		return apps, nil
	}

	return nil, errors.New("empty response")
}
