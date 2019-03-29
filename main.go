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
	"github.com/VirgilSecurity/virgil-cli/client"
	"log"
	"os"

	"github.com/VirgilSecurity/virgil-cli/cmd"
	"gopkg.in/urfave/cli.v2/altsrc"

	"gopkg.in/urfave/cli.v2"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	flags := []cli.Flag{
		&cli.StringFlag{
			Name:    "config",
			Aliases: []string{"cfg"},
			Usage:   "Yaml config file path",
		},
		altsrc.NewStringFlag(&cli.StringFlag{
			Name:    "service_url",
			Aliases: []string{"url"},
			Usage:   "Dashboard service URL",
			EnvVars: []string{"DASHBOARD_URL"},
			Hidden:  true,
		}),
	}

	if commit != "none" {
		commit = commit[:8]
	}

	vcli := &client.VirgilHttpClient{
		Address: "https://dashboard.virgilsecurity.com/api/",
	}

	app := &cli.App{
		Version:               fmt.Sprintf("%v, commit %v, built %v", version, commit, date),
		Name:                  "CLI",
		Usage:                 "VirgilSecurity command line interface",
		Flags:                 flags,
		EnableShellCompletion: true,
		Commands: []*cli.Command{
			cmd.Register(vcli),
			cmd.Login(vcli),
			cmd.Logout(vcli),
			cmd.Application(vcli),
			cmd.Key(vcli),
			cmd.UseApp(vcli),
			cmd.PureKit(),
		},
		Before: func(c *cli.Context) error {

			url := c.String("service_url")
			if url != "" {
				vcli.Address = url
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
