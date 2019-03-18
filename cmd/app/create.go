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
	"bufio"
	"fmt"
	"net/http"
	"os"

	"github.com/VirgilSecurity/virgil-cli/utils"

	"github.com/VirgilSecurity/virgil-cli/models"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/pkg/errors"
	"gopkg.in/urfave/cli.v2"
)

func Create(vcli *client.VirgilHttpClient) *cli.Command {
	return &cli.Command{
		Name:      "create",
		Aliases:   []string{"c"},
		ArgsUsage: "app_name",
		Usage:     "Create a new app",
		Action: func(context *cli.Context) (err error) {

			if context.NArg() < 1 {
				return errors.New("Invalid number of arguments. Please, specify application name")
			}

			name := context.Args().First()

			var appID string
			appID, err = CreateFunc(name, vcli)

			if err != nil {
				return err
			}

			fmt.Println("APP_ID:", appID)
			utils.SaveAppID(appID)
			return nil
		},
	}
}

func CreateFunc(name string, vcli *client.VirgilHttpClient) (appID string, err error) {

	fmt.Println("Enter new app description:")
	scanner := bufio.NewScanner(os.Stdin)

	description := ""
	for description == "" {
		scanner.Scan()
		description = scanner.Text()
		if description == "" {
			fmt.Println("description can't be empty")
			fmt.Println("Enter new app description:")
		}
	}

	req := &models.CreateAppRequest{Name: name, Description: description, Type: "pki"}
	resp := &models.Application{}

	token, err := utils.LoadAccessTokenOrLogin(vcli)

	if err != nil {
		return "", err
	}

	for err == nil {
		_, _, vErr := vcli.Send(http.MethodPost, token, "applications", req, resp)
		if vErr == nil {
			break
		}

		token, err = utils.CheckRetry(vErr, vcli)
	}

	if err != nil {
		return
	}

	if resp != nil {
		return resp.ID, nil
	}

	return "", errors.New("empty response")
}
