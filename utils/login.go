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

package utils

import (
	"bufio"
	"fmt"
	"github.com/pkg/errors"
	"net/http"
	"os"
	"strings"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/models"
	"github.com/google/uuid"
	"github.com/howeyc/gopass"
)

//Login obtains temporary account access token. Email and password may be empty
func Login(email, password string, vcli *client.VirgilHttpClient) (err error) {

	if email == "" {
		fmt.Println("Enter your email:")

		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()

		email = strings.TrimSpace(scanner.Text())
	}

	if password == "" {
		pwd, err := gopass.GetPasswdPrompt("Enter account password:\r\n", false, os.Stdin, os.Stdout)
		if err != nil {
			return err
		}
		password = string(pwd)
	}

	req := &models.LoginRequest{
		Email:    email,
		Password: password,
	}

	sessionToken := models.SessionToken{}

	_, _, vErr := vcli.Send(http.MethodPost, "user/login", req, &sessionToken, nil)
	if vErr != nil {
		fmt.Println(vErr)
		_, err = CheckRetry(vErr, vcli)
		if err == ErrEmptyMFACode {
			code, err := gopass.GetPasswdPrompt("Enter 2-factor code:\r\n", true, os.Stdin, os.Stdout)
			if err != nil {
				return err
			}
			req.Verification = &models.Verification{MFACode: string(code)}
			_, _, vErr = vcli.Send(http.MethodPost, "user/login", req, &sessionToken, nil)

			if vErr != nil {
				return errors.New(fmt.Sprintf("Authorization failed.\n"))
			}
		} else if err != nil {
			return err
		}
	}

	tokenName := uuid.New()
	if err != nil {
		return err
	}
	header := http.Header{}
	header.Set("SessionToken", sessionToken.Token)
	managementToken := models.ManagementTokenResponse{}
	_, _, vErr = vcli.Send(http.MethodPost, "management-token",
		models.ManagementTokenRequest{Name: tokenName.String()},
		&managementToken, header)
	if vErr != nil {
		return errors.New(fmt.Sprintf("Authorization failed.\n"))
	}

	return SaveAccessToken(managementToken.Token)
}

func LoadAccessTokenOrLogin(vcli *client.VirgilHttpClient) (token string, err error) {
	token, err = LoadAccessToken()
	if err != nil {
		err = Login("", "", vcli)
		if err != nil {
			return "", err
		}
		return LoadAccessToken()
	}
	return
}
