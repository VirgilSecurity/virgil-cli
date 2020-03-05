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
	"os"
	"strings"

	"github.com/howeyc/gopass"
	"github.com/urfave/cli/v2"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

func Login(client *client.VirgilHTTPClient) *cli.Command {
	return &cli.Command{
		Name:  "login",
		Usage: "Open user session",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "username", Aliases: []string{"u"}, Usage: "user email"},
			&cli.StringFlag{Name: "password", Aliases: []string{"p"}, Usage: "user password"},
		},
		Action: func(context *cli.Context) error {
			_ = utils.DeleteAccessToken()
			_ = utils.DeleteAppFile()

			email := utils.ReadFlagOrDefault(context, "username", "")
			pwd := utils.ReadFlagOrDefault(context, "password", "")

			if email == "" {
				email = strings.TrimSpace(utils.ReadParamOrDefaultOrFromConsole(context, "email", utils.EmailPrompt, ""))
			}

			if pwd == "" {
				pwdBytes, err := gopass.GetPasswdPrompt(utils.PasswordPrompt+"\r\n", false, os.Stdin, os.Stdout)
				if err != nil {
					return utils.CliExit(err)
				}

				pwd = string(pwdBytes)
			}

			err := utils.Login(email, pwd, client)

			if err == nil {
				fmt.Printf("%s %s", utils.LoginSuccess, email)
				return err
			}

			return utils.CliExit(err)
		},
	}
}
