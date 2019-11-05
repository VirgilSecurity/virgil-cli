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
	"net/http"

	"github.com/VirgilSecurity/virgil-cli/client"
)

func SendWithCheckRetry(
	vcli *client.VirgilHTTPClient,
	method string,
	urlPath string,
	payload interface{},
	respObj interface{},
	extraOptions ...interface{},
) (headers http.Header, cookie string, err error) {

	token := ""
	if len(extraOptions) == 0 {
		token, err = LoadAccessTokenOrLogin(vcli)

		if err != nil {
			return nil, "", err
		}

	}
	header := http.Header{}

	if len(extraOptions) > 0 {
		t, ok := extraOptions[0].(string)
		if ok && t[:2] == "MT" {
			header.Add("SessionToken", t)
		} else {
			header.Add("AppToken", t)
		}
	} else if token != "" {
		header.Add("ManagementToken", token)
	}

	var vErr *client.VirgilAPIError
	for vErr == nil {
		_, _, vErr = vcli.Send(method, urlPath, payload, respObj, header)
		if vErr == nil {
			break
		}

		_, err = CheckRetry(vErr, vcli)
	}

	return nil, "", err
}
