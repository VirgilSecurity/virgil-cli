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

package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/urfave/cli/v2"
	"github.com/urfave/cli/v2/altsrc"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/cmd"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

func main() {
	flags := []cli.Flag{
		&cli.StringFlag{
			Name:    "config",
			Aliases: []string{"cfg"},
			Usage:   "Yaml config file path",
		},
		altsrc.NewStringFlag(&cli.StringFlag{
			Name:    "api_gateway_url",
			Usage:   "Api gateway URL",
			EnvVars: []string{"VIRGIL_API_URL"},
			Hidden:  true,
		}),
	}

	apiGatewayClient := &client.VirgilHTTPClient{
		Address: "https://api.virgilsecurity.com/management/v1/",
	}

	kmsClient := &client.VirgilHTTPClient{
		Address: "https://api.virgilsecurity.com/",
	}

	app := &cli.App{
		Version:              fmt.Sprintf("%v", utils.Version),
		Name:                 "CLI",
		Usage:                "VirgilSecurity command line interface",
		Flags:                flags,
		EnableBashCompletion: true,
		Commands: []*cli.Command{
			cmd.Register(apiGatewayClient),
			cmd.Login(apiGatewayClient),
			cmd.Logout(),
			cmd.Application(apiGatewayClient),
			cmd.UseApp(apiGatewayClient),
			cmd.PureKit(),
			cmd.Keygen(),
			cmd.Key2Pub(),
			cmd.Encrypt(),
			cmd.Decrypt(),
			cmd.Sign(),
			cmd.Verify(),
			cmd.Cards(apiGatewayClient),
			cmd.Wave(apiGatewayClient),
			cmd.KMS(kmsClient),
		},
		Before: func(c *cli.Context) error {
			apiURL := c.String("api_gateway_url")
			if strings.TrimSpace(apiURL) != "" {
				apiGatewayClient.Address = apiURL
				kmsClient.Address = strings.TrimSuffix(apiURL, "management/v1/")
			}

			if _, err := os.Stat(c.String("config")); os.IsNotExist(err) {
				return nil
			}

			return altsrc.InitInputSourceWithContext(flags, altsrc.NewYamlSourceFromFlagFunc("config"))(c)
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
