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
	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/models"
	"github.com/VirgilSecurity/virgil-cli/utils"
	"github.com/pkg/errors"
	"gopkg.in/urfave/cli.v2"
	"net/http"
	"strings"
)

func UseApp(client *client.VirgilHttpClient) *cli.Command {
	return &cli.Command{
		Name:      "use app",
		Aliases:   []string{"use"},
		ArgsUsage: "name",
		Usage:     "Changes context to app with specified name",
		Action: func(context *cli.Context) error {
			return useFunc(context, client)
		},
	}
}

func useFunc(context *cli.Context, vcli *client.VirgilHttpClient) error {

	if context.NArg() < 1 {
		return errors.New("Invalid number of arguments. Please, specify application name")
	}

	appName := strings.Join(context.Args().Slice(), " ")

	token, err := utils.LoadAccessTokenOrLogin(vcli)

	if err != nil {
		return err
	}

	var apps []*models.Application
	apps, err = listFunc(token, vcli)

	if err != nil {
		return err
	}

	for _, app := range apps {
		if app.Name == appName {
			utils.SaveDefaultApp(app)
			fmt.Println("Application context set")
			return nil
		}
	}

	return errors.New("there is no app with name " + appName)
}

func listFunc(token string, vcli *client.VirgilHttpClient) (apps []*models.Application, err error) {

	for err == nil {
		_, _, vErr := vcli.Send(http.MethodGet, token, "applications", nil, &apps)
		if err == nil {
			break
		}

		token, err = utils.CheckRetry(vErr, vcli)
	}

	if err != nil {
		return apps, err
	}

	if apps != nil {
		return apps, nil
	}

	return nil, errors.New("empty response")
}
