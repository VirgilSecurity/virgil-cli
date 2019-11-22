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

	"gopkg.in/urfave/cli.v2"
	"gopkg.in/urfave/cli.v2/altsrc"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/cmd"
)

var (
	version = "5.1.7"
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

	app := &cli.App{
		Version:               fmt.Sprintf("%v", version),
		Name:                  "CLI",
		Usage:                 "VirgilSecurity command line interface",
		Flags:                 flags,
		EnableShellCompletion: true,
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
		},
		Before: func(c *cli.Context) error {
			apiURL := c.String("api_gateway_url")
			if strings.TrimSpace(apiURL) != "" {
				apiGatewayClient.Address = apiURL
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
