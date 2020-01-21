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

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/models"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

func Create(vcli *client.VirgilHTTPClient) *cli.Command {
	return &cli.Command{
		Name:      "create",
		Aliases:   []string{"c"},
		ArgsUsage: "app_name",
		Usage:     "Create a new app",
		Flags:     []cli.Flag{&cli.StringFlag{Name: "type", Usage: "application type (e2ee or pure)"}},

		Action: func(context *cli.Context) (err error) {
			name := utils.ReadParamOrDefaultOrFromConsole(context, "name", "Enter application name", "")
			var appID string

			appID, err = CreateFunc(name, vcli)

			if err != nil {
				return err
			}

			fmt.Println("App ID:", appID)
			fmt.Println("Application has been successfully created.")
			return nil
		},
	}
}

func CreateFunc(name string, vcli *client.VirgilHTTPClient) (appID string, err error) {
	req := &models.CreateAppRequest{Name: name, Type: "pki"}
	resp := &models.Application{}

	_, _, err = utils.SendWithCheckRetry(vcli, http.MethodPost, "application", req, resp)

	if err != nil {
		return
	}

	if resp != nil {
		return resp.ID, nil
	}

	return "", errors.New("empty response")
}
