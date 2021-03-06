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

func Update(vcli *client.VirgilHTTPClient) *cli.Command {
	return &cli.Command{
		Name:      "update",
		Aliases:   []string{"u"},
		ArgsUsage: "app_id",
		Usage:     "Update app by id",
		Action: func(context *cli.Context) (err error) {
			defaultApp, _ := utils.LoadDefaultApp()
			defaultAppID := ""
			if defaultApp != nil {
				defaultAppID = defaultApp.ID
			}

			appID := utils.ReadParamOrDefaultOrFromConsole(context, "appID", utils.ApplicationIDPrompt, defaultAppID)

			_, err = getApp(appID, vcli)
			if err != nil {
				return utils.CliExit(err)
			}
			err = UpdateFunc(appID, vcli)

			if err == nil {
				fmt.Println(utils.ApplicationUpdateSuccess)
			} else if err == utils.ErrEntityNotFound {
				return utils.CliExit(errors.New(fmt.Sprintf("%s %s\n", utils.ApplicationNotFound, appID)))
			}

			if err != nil {
				return utils.CliExit(err)
			}
			return err
		},
	}
}

func UpdateFunc(appID string, vcli *client.VirgilHTTPClient) (err error) {
	name := utils.ReadConsoleValue("name", utils.ApplicationNamePrompt)

	req := &models.UpdateAppRequest{Name: name}

	_, _, err = utils.SendWithCheckRetry(vcli, http.MethodPut, "application/"+appID, req, nil)

	return err
}
