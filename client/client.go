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

package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"runtime"

	"github.com/golang/protobuf/proto"

	"github.com/VirgilSecurity/virgil-cli/client/protobuf"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

var (
	virgilAgent = fmt.Sprintf("cli;;%s;%s", runtime.GOOS, utils.Version)
)

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type VirgilHTTPClient struct {
	Client  HTTPClient
	Address string
}

func (vc *VirgilHTTPClient) Send(
	method string,
	urlPath string,
	payload interface{},
	respObj interface{},
	header http.Header,
) (headers http.Header, cookie string, virgilAPIErr *VirgilAPIError) {

	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, cookie, &VirgilAPIError{Message: fmt.Sprintf("VirgilHTTPClient.Send: marshal payload: %v", err)}
		}
	}

	u, err := url.Parse(vc.Address)
	if err != nil {
		return nil, cookie, &VirgilAPIError{Message: fmt.Sprintf("VirgilHTTPClient.Send: URL parse: %v", err)}
	}

	u.Path = path.Join(u.Path, urlPath)
	req, err := http.NewRequest(method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, cookie, &VirgilAPIError{Message: fmt.Sprintf("VirgilHTTPClient.Send: new request: %v", err)}
	}

	if len(header) != 0 {
		req.Header = header
	}
	req.Header.Set("Virgil-Agent", virgilAgent)

	client := vc.getHTTPClient()

	resp, err := client.Do(req)
	if err != nil {
		return nil, cookie, &VirgilAPIError{Message: fmt.Sprintf("VirgilHTTPClient.Send: send request: %v", err)}
	}
	// nolint: errcheck
	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, cookie, &VirgilAPIError{Message: fmt.Sprintf("VirgilHTTPClient.Send: read body: %v", err)}
	}

	for _, c := range resp.Cookies() {
		if c.Name == "gosession" {
			cookie = c.Value
		}
	}

	if resp.StatusCode/100 == 2 {
		if respObj == nil {
			return resp.Header, cookie, nil
		}
		if err = json.Unmarshal(body, &respObj); err != nil {
			return nil, cookie, &VirgilAPIError{Message: fmt.Sprintf("VirgilHTTPClient.Send: unmarshal response object: %v", err)}
		}
		return resp.Header, cookie, nil
	}

	if len(body) == 0 {
		return nil, cookie, &VirgilAPIError{StatusCode: resp.StatusCode}
	}

	var httpErr *VirgilAPIError
	err = json.Unmarshal(body, &httpErr)
	if err != nil {
		return nil, cookie, &VirgilAPIError{Message: fmt.Sprintf("VirgilHTTPClient.Send: unmarshal response object: %v", err)}
	}

	return nil, cookie, httpErr
}

func (vc *VirgilHTTPClient) SendProto(
	method string,
	urlPath string,
	body []byte,
	respObj *[]byte,
	header http.Header,
) (headers http.Header, cookie string, virgilAPIErr *VirgilAPIError) {

	u, err := url.Parse(vc.Address)
	if err != nil {
		return nil, cookie, &VirgilAPIError{Message: fmt.Sprintf("VirgilHTTPClient.SendProto: URL parse: %v", err)}
	}

	u.Path = path.Join(u.Path, urlPath)
	req, err := http.NewRequest(method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, cookie, &VirgilAPIError{Message: fmt.Sprintf("VirgilHTTPClient.SendProto: new request: %v", err)}
	}

	if len(header) != 0 {
		req.Header = header
	}

	client := vc.getHTTPClient()

	resp, err := client.Do(req)
	if err != nil {
		return nil, cookie, &VirgilAPIError{Message: fmt.Sprintf("VirgilHTTPClient.SendProto: send request: %v", err)}
	}
	// nolint: errcheck
	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, cookie, &VirgilAPIError{Message: fmt.Sprintf("VirgilHTTPClient.SendProto: read body: %v", err)}
	}

	for _, c := range resp.Cookies() {
		if c.Name == "gosession" {
			cookie = c.Value
		}
	}

	if resp.StatusCode/100 == 2 {
		if respObj == nil {
			return resp.Header, cookie, nil
		}
		*respObj = body
		return resp.Header, cookie, nil
	}

	if len(body) == 0 {
		return nil, cookie, &VirgilAPIError{StatusCode: resp.StatusCode}
	}

	protoHTTPErr := &protobuf.HttpError{}
	if err := proto.Unmarshal(body, protoHTTPErr); err != nil {
		return nil, cookie, &VirgilAPIError{Message: fmt.Sprintf("VirgilHTTPClient.SendProto: unmarshal protobuf response object: %v", err)}
	}
	httpErr := &VirgilAPIError{Code: int(protoHTTPErr.Code), Message: protoHTTPErr.Message}

	return nil, cookie, httpErr
}

type VirgilAPIError struct {
	StatusCode int
	Code       int          `json:"code"`
	Message    string       `json:"message"`
	Errors     []ErrorField `json:"errors,omitempty"`
}

func (err VirgilAPIError) Error() string {
	return fmt.Sprintf("Virgil API error {code: %v message: %v errors: %v}", err.Code, err.Message, err.Errors)
}

type ErrorField struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Field   string `json:"field"`
}

func (err ErrorField) String() string {
	return fmt.Sprintf("Virgil Error field {code: %v message: %v field: %v}", err.Code, err.Message, err.Field)
}

func (vc *VirgilHTTPClient) getHTTPClient() HTTPClient {
	if vc.Client != nil {
		return vc.Client
	}
	return http.DefaultClient
}
