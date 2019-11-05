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
	"gopkg.in/urfave/cli.v2"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/models"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

func Register(client *client.VirgilHTTPClient) *cli.Command {
	return &cli.Command{
		Name:      "register",
		ArgsUsage: "email",
		Usage:     "Register a new account",
		Action: func(context *cli.Context) error {
			return registerFunc(context, client)
		},
	}
}

func registerFunc(context *cli.Context, vcli *client.VirgilHTTPClient) error {
	_ = utils.DeleteAccessToken()
	_ = utils.DeleteAppFile()

	email := strings.TrimSpace(utils.ReadParamOrDefaultOrFromConsole(context, "email", "Enter email", ""))

	pwd, err := gopass.GetPasswdPrompt("Enter the account password:\r\n", false, os.Stdin, os.Stdout)
	if err != nil {
		return err
	}
	pwdAgain, err := gopass.GetPasswdPrompt("Again:\r\n", false, os.Stdin, os.Stdout)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(pwd, pwdAgain) != 1 {
		err = errors.New("passwords do not match")
		return err
	}

	req := &models.CreateAccountRequest{Email: email, Password: string(pwd)}

	_, _, vErr := vcli.Send(http.MethodPost, "user/register", req, nil, nil)

	if vErr != nil {
		return vErr
	}
	err = utils.Login(email, string(pwd), vcli)

	if err != nil {
		return err
	}

	fmt.Println("Account has been successfully registered.")

	return nil
}
