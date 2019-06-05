/*
 * Copyright (C) 2015-2018 Virgil Security Inc.
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

package purekit

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"path"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"

	"github.com/pkg/errors"
)

// HTTPClient describes transport layer
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

//VirgilHTTPClient implements transport layer
type VirgilHTTPClient struct {
	Client  HTTPClient
	Address string
	once    sync.Once
}

//Send performs http request with protobuf encoded payload & response
func (vc *VirgilHTTPClient) Send(token string, method string, urlPath string, payload proto.Message, respObj proto.Message) (headers http.Header, err error) {
	var body []byte
	if payload != nil {
		body, err = proto.Marshal(payload)
		if err != nil {
			return nil, errors.Wrap(err, "VirgilHTTPClient.Send: marshal payload")
		}
	}

	u, err := url.Parse(vc.Address)
	if err != nil {
		return nil, errors.Wrap(err, "VirgilHTTPClient.Send: URL parse")
	}

	u.Path = path.Join(u.Path, urlPath)
	req, err := http.NewRequest(method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errors.Wrap(err, "VirgilHTTPClient.Send: new request")
	}

	req.Header.Add("Virgil-Agent", getAgentHeader())

	if token != "" {
		req.Header.Add("AppToken", token)
	}

	client := vc.getHTTPClient()

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "VirgilHTTPClient.Send: send request")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		if respObj != nil {

			body, err = ioutil.ReadAll(resp.Body)

			if err != nil {
				return nil, errors.Wrap(err, "VirgilHTTPClient.Send: read body")
			}

			err = proto.Unmarshal(body, respObj)
			if err != nil {
				return nil, errors.Wrap(err, "VirgilHTTPClient.Send: unmarshal response object")
			}
		}
		return resp.Header, nil
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "VirgilHTTPClient.Send: read response body")
	}

	if len(respBody) > 0 {
		httpErr := &HttpError{}
		err = proto.Unmarshal(respBody, httpErr)
		if err == nil {

			return nil, httpErr
		}
	}

	return nil, fmt.Errorf("%d %s", resp.StatusCode, string(respBody))
}

func (vc *VirgilHTTPClient) getHTTPClient() HTTPClient {

	vc.once.Do(func() {

		if vc.Client == nil {

			dialer := &net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 10 * time.Second,
				DualStack: true,
			}

			var netTransport = &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.DialContext(ctx, network, addr)
				},
				TLSHandshakeTimeout: 10 * time.Second,
			}
			var cli = &http.Client{
				Timeout:   10 * time.Second,
				Transport: netTransport,
			}

			vc.Client = cli
		}
	})

	return vc.Client
}
