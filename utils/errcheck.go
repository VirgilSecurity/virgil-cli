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

	"github.com/VirgilSecurity/virgil-cli/client"
)

var (
	ErrEntityNotFound               = fmt.Errorf("entity not found")
	ErrEmailIsNotConfirmed          = fmt.Errorf("email is not confirmed")
	ErrApplicationAlreadyRegistered = fmt.Errorf("error: application with given name already registered")
	ErrAuthFailed                   = fmt.Errorf("authorization failed: incorrect email or password")
	ErrApiKeyAlreadyRegistered      = fmt.Errorf("error: api key with given name already registered")
	ErrEmptyMFACode                 = fmt.Errorf("error: Multi factor authorization code is empty field")
	ErrPasswordTooWeak              = fmt.Errorf("error: Password is too weak: password must be at least 8 characters length")
	ErrIncorrectAppToken            = fmt.Errorf("error: application token is incorrect")
)

func CheckRetry(errToCheck *client.VirgilAPIError, vcli *client.VirgilHttpClient) (token string, err error) {

	if errToCheck == nil {
		return "", nil
	}
	if errToCheck.StatusCode == http.StatusUnauthorized || errToCheck.Code == 40100 {
		err = Login("", "", vcli)
		if err != nil {
			return
		}
		return LoadAccessToken()
	}

	if errToCheck.StatusCode == http.StatusNotFound ||
		errToCheck.Code == 40015 ||
		errToCheck.Code == 40000 && len(errToCheck.Errors) >= 1 && errToCheck.Errors[0].Code == 40400 ||
		strings.Contains(errToCheck.Error(), "Entity was not found ") {
		return "", ErrEntityNotFound
	}
	if errToCheck.Code == 40000 && len(errToCheck.Errors) >= 1 && errToCheck.Errors[0].Code == 40001 &&
		strings.Contains(errToCheck.Errors[0].Message, "Invalid email or password") {
		return "", ErrAuthFailed
	}
	if errToCheck.Code == 40000 && len(errToCheck.Errors) >= 1 && errToCheck.Errors[0].Code == 40002 &&
		strings.Contains(errToCheck.Errors[0].Message, "Application with given name already registered") {
		return "", ErrApplicationAlreadyRegistered
	}
	if errToCheck.Code == 40000 && len(errToCheck.Errors) >= 1 && errToCheck.Errors[0].Code == 40002 &&
		strings.Contains(errToCheck.Errors[0].Message, "Email is not valid") {
		return "", ErrAuthFailed
	}
	if errToCheck.Code == 40000 && len(errToCheck.Errors) >= 1 && errToCheck.Errors[0].Code == 40002 &&
		strings.Contains(errToCheck.Errors[0].Message, "Email is empty") {
		return "", ErrAuthFailed
	}
	if errToCheck.Code == 40000 && len(errToCheck.Errors) >= 1 && errToCheck.Errors[0].Code == 40003 &&
		strings.Contains(errToCheck.Errors[0].Message, "Password is invalid") {
		return "", ErrAuthFailed
	}
	if errToCheck.Code == 40000 && len(errToCheck.Errors) >= 1 && errToCheck.Errors[0].Code == 40004 &&
		strings.Contains(errToCheck.Errors[0].Message, "Password is invalid") {
		return "", ErrPasswordTooWeak
	}
	if errToCheck.Code == 40000 && len(errToCheck.Errors) >= 1 && errToCheck.Errors[0].Code == 40003 &&
		strings.Contains(errToCheck.Errors[0].Message, "Password is empty") {
		return "", ErrAuthFailed
	}
	if errToCheck.Code == 40000 && len(errToCheck.Errors) >= 1 && errToCheck.Errors[0].Code == 40003 &&
		strings.Contains(errToCheck.Errors[0].Message, "Access Key already registered with given name") {
		return "", ErrApiKeyAlreadyRegistered
	}
	if errToCheck.Code == 40000 && len(errToCheck.Errors) >= 1 && errToCheck.Errors[0].Code == 40098 {
		return "", ErrEmptyMFACode
	}
	if errToCheck.Code == 40020 {
		return "", ErrPasswordTooWeak
	}
	if errToCheck.Code == 40300 {
		return "", ErrEmailIsNotConfirmed
	}
	if errToCheck.Code == 20303 || errToCheck.Code == 20308 {
		return "", ErrIncorrectAppToken
	}
	fmt.Println("error sending request to " + vcli.Address)
	return "", errToCheck
}
