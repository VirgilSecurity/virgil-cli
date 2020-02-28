/*
 * Copyright (C) 2015-2020 Virgil Security Inc.
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
package device

import (
	"fmt"
	"net/http"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/models"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

func List(vcli *client.VirgilHTTPClient) *cli.Command {
	return &cli.Command{
		Name:    "list",
		Aliases: []string{"l"},
		Usage:   "List your devices",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "app-token", Usage: "application token"}},
		Action: func(context *cli.Context) (err error) {
			defaultApp, _ := utils.LoadDefaultApp()
			defaultAppToken := ""
			if defaultApp != nil {
				defaultAppToken = defaultApp.Token
			}
			appToken := utils.ReadFlagOrDefault(context, "app-token", defaultAppToken)
			if appToken == "" {
				return utils.CliExit(errors.New(utils.SpecifyAppTokenFlag))
			}

			devices, err := deviceListFunc(appToken, vcli)
			if err != nil {
				return utils.CliExit(err)
			}

			if len(devices) == 0 {
				fmt.Println(utils.SCMSDeviceNotYetRegistered)
				return nil
			}

			fmt.Printf("|%25s|%35s|%20s|%20s\n", "Device id    ", "dcm id   ", " valid_from ", " valid_to ")
			fmt.Printf("|%25s|%35s|%20s|%20s\n",
				"-------------------------",
				"-----------------------------------",
				"---------------------------------------",
				"---------------------------------------",
			)
			for _, d := range devices {
				fmt.Printf("|%25s|%35s| %19s | %19s\n", d.ID, d.DcmID, d.ValidFrom, d.ValidTo)
			}
			return nil
		},
	}
}

func deviceListFunc(appToken string, vcli *client.VirgilHTTPClient) (devices []*models.Device, err error) {
	_, _, err = utils.SendWithCheckRetry(vcli, http.MethodGet, "scms/devices", nil, &devices, appToken)

	if err != nil {
		return
	}

	if devices != nil {
		return devices, nil
	}

	return nil, errors.New("empty response")
}
