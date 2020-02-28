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
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/howeyc/gopass"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/models"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

func Register(client *client.VirgilHTTPClient) *cli.Command {
	return &cli.Command{
		Name:      "register",
		ArgsUsage: "email",
		Usage:     "Register a new account",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "username", Aliases: []string{"u"}, Usage: "user email"},
			&cli.StringFlag{Name: "password", Aliases: []string{"p"}, Usage: "user password"},
		},
		Action: func(context *cli.Context) error {
			return registerFunc(context, client)
		},
	}
}

func registerFunc(context *cli.Context, vcli *client.VirgilHTTPClient) (err error) {
	email := utils.ReadFlagOrDefault(context, "username", "")
	pwd := utils.ReadFlagOrDefault(context, "password", "")

	_ = utils.DeleteAccessToken()
	_ = utils.DeleteAppFile()

	if email == "" {
		email = strings.TrimSpace(utils.ReadParamOrDefaultOrFromConsole(context, "email", utils.EmailPrompt, ""))
	}

	if pwd == "" {
		pwdBytes, err := gopass.GetPasswdPrompt(utils.PasswordPrompt+"\r\n", false, os.Stdin, os.Stdout)
		if err != nil {
			return utils.CliExit(err)
		}
		pwdAgainBytes, err := gopass.GetPasswdPrompt(utils.PasswordConfirmPrompt+"\r\n", false, os.Stdin, os.Stdout)
		if err != nil {
			return utils.CliExit(err)
		}

		if subtle.ConstantTimeCompare(pwdBytes, pwdAgainBytes) != 1 {
			err = errors.New(utils.PasswordsDoesntMatch)
			return utils.CliExit(err)
		}
		pwd = string(pwdBytes)
	}

	req := &models.CreateAccountRequest{Email: email, Password: pwd}

	_, _, vErr := vcli.Send(http.MethodPost, "user/register", req, nil, nil)

	if vErr != nil {
		return utils.CliExitVirgil(vErr)
	}
	err = utils.Login(email, pwd, vcli)

	if err != nil {
		return utils.CliExit(err)
	}

	fmt.Println(utils.AccountSuccessfullyRegistered)

	return nil
}
