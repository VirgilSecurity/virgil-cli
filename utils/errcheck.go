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
	"fmt"
	"net/http"
	"strings"

	"github.com/urfave/cli/v2"

	"github.com/VirgilSecurity/virgil-cli/client"
)

var (
	ErrEntityNotFound               = fmt.Errorf("entity not found")
	ErrEmailIsNotConfirmed          = fmt.Errorf("user email has not been confirmed")
	ErrApplicationAlreadyRegistered = fmt.Errorf("application with given name already registered")
	ErrAuthFailed                   = fmt.Errorf("this email and password combination does not exist")
	ErrAPIKeyAlreadyRegistered      = fmt.Errorf("api key with given name already registered")
	ErrEmptyMFACode                 = fmt.Errorf("multi factor authorization code is empty field")
	ErrPasswordTooWeak              = fmt.Errorf("password is too weak: password must be at least 8 characters length")
	ErrIncorrectAppToken            = fmt.Errorf("application token is incorrect")
	ErrInvalidConfirmationCode      = fmt.Errorf("confirmation code is invalid")
	ErrEmailAlreadyRegistered       = fmt.Errorf("account with this email has been already registered")
)

func CliExit(err interface{}) error {
	verr, ok := err.(*client.VirgilAPIError)
	if ok {
		return cli.Exit(fmt.Sprintf("Error: %s", verr.Message), 1)
	}

	cerr, ok := err.(cli.ExitCoder)
	if ok {
		return cli.Exit(cerr.Error(), cerr.ExitCode())
	}

	return cli.Exit(fmt.Sprintf("Error: %s", err), 1)
}

func CheckRetry(errToCheck *client.VirgilAPIError, vcli *client.VirgilHTTPClient) (token string, err error) {
	if errToCheck == nil {
		return "", nil
	}

	if isUnauthorized(errToCheck) {
		if err = Login("", "", vcli); err != nil {
			return "", err
		}
		return LoadAccessToken()
	}
	if isEntityNotFound(errToCheck) {
		return "", ErrEntityNotFound
	}
	if isAuthFailed(errToCheck) {
		return "", ErrAuthFailed
	}

	switch errToCheck.Code {
	case 40000:
		return "", checkCode40000(errToCheck, vcli.Address)
	case 40020:
		return "", ErrPasswordTooWeak
	case 40024: // user account is already activated
		return "", nil
	case 40026:
		return "", ErrInvalidConfirmationCode
	case 40029:
		return "", ErrEmptyMFACode
	case 40033:
		return "", ErrEmailIsNotConfirmed
	case 40052:
		return "", ErrEmailAlreadyRegistered
	case 20303:
		return "", ErrIncorrectAppToken
	case 20308:
		return "", ErrIncorrectAppToken
	}

	// fmt.Println("error sending request to " + vcli.Address)
	return "", errToCheck
}

func isUnauthorized(err *client.VirgilAPIError) bool {
	return err.StatusCode == http.StatusUnauthorized ||
		err.Code == 40100 ||
		err.Code == 20311
}

func isEntityNotFound(err *client.VirgilAPIError) bool {
	result := err.StatusCode == http.StatusNotFound ||
		err.Code == 40015 ||
		strings.Contains(err.Error(), "Entity was not found")

	if len(err.Errors) != 0 {
		result = result || err.Errors[0].Code == 40400
	}
	return result
}

func isAuthFailed(err *client.VirgilAPIError) bool {
	result := err.Code == 40019 || err.Code == 40027
	if len(err.Errors) != 0 {
		errField := err.Errors[0]

		result = result || errField.Code == 40001 && strings.Contains(errField.Message, "Invalid email or password")
		result = result || errField.Code == 40002 && strings.Contains(errField.Message, "Email is not valid")
		result = result || errField.Code == 40002 && strings.Contains(errField.Message, "Email is empty")
		result = result || errField.Code == 40003 && strings.Contains(errField.Message, "Password is invalid")
		result = result || errField.Code == 40003 && strings.Contains(errField.Message, "Password is empty")
	}
	return result
}

func checkCode40000(err *client.VirgilAPIError, addr string) error {
	if len(err.Errors) == 0 {
		// fmt.Println("error sending request to " + addr)
		return err
	}

	errField := err.Errors[0]
	if errField.Code == 40002 && strings.Contains(errField.Message, "Application with given name already registered") {
		return ErrApplicationAlreadyRegistered
	}
	if errField.Code == 40003 && strings.Contains(errField.Message, "Access Key already registered with given name") {
		return ErrAPIKeyAlreadyRegistered
	}
	if errField.Code == 40004 && strings.Contains(errField.Message, "Password is invalid") {
		return ErrPasswordTooWeak
	}

	// fmt.Println("error sending request to " + addr)
	return err
}
