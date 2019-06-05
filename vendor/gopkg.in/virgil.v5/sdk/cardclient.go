/*
 * Copyright (C) 2015-2018 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   (1) Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   (2) Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 *   (3) Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
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
 */

package sdk

import (
	"net/http"

	"sync"

	"encoding/hex"

	"gopkg.in/virgil.v5/common"
	"gopkg.in/virgil.v5/errors"
)

type CardClient struct {
	ServiceURL       string
	VirgilHttpClient *common.VirgilHttpClient
	HttpClient       common.HttpClient
	once             sync.Once
}

func NewCardsClient(serviceURL string) *CardClient {
	return &CardClient{ServiceURL: serviceURL}
}

func (c *CardClient) PublishCard(rawCard *RawSignedModel, token string) (*RawSignedModel, error) {
	var returnedRawCard *RawSignedModel
	_, err := c.send(http.MethodPost, "/card/v5", token, rawCard, &returnedRawCard)
	return returnedRawCard, err
}

func (c *CardClient) SearchCards(identity string, token string) ([]*RawSignedModel, error) {
	var rawCards []*RawSignedModel
	_, err := c.send(http.MethodPost, "/card/v5/actions/search", token, map[string]string{"identity": identity}, &rawCards)
	if err != nil {
		return nil, err
	}

	return rawCards, err
}

func (c *CardClient) GetCard(cardId string, token string) (*RawSignedModel, bool, error) {

	const (
		SupersededCardIDHTTPHeader      = "X-Virgil-Is-Superseeded"
		SupersededCardIDHTTPHeaderValue = "true"
	)

	if _, err := hex.DecodeString(cardId); err != nil || len(cardId) != 64 {
		return nil, false, errors.New("invalid card id")
	}

	var rawCard *RawSignedModel
	headers, err := c.send(http.MethodGet, "/card/v5/"+cardId, token, nil, &rawCard)

	var outdated bool
	if headers != nil {
		outdated = headers.Get(SupersededCardIDHTTPHeader) == SupersededCardIDHTTPHeaderValue
	}

	return rawCard, outdated, err
}

func (c *CardClient) send(method string, url string, token string, payload interface{}, respObj interface{}) (headers http.Header, err error) {
	client := c.getVirgilClient()
	headers, httpCode, err := client.Send(method, url, token, payload, respObj)
	if err != nil {
		if apiErr, ok := err.(common.VirgilAPIError); ok {
			return headers, errors.NewServiceError(apiErr.Code, httpCode, apiErr.Message)
		}
		return headers, errors.NewServiceError(0, httpCode, err.Error())
	}
	return headers, nil
}

func (c *CardClient) getUrl() string {
	if c.ServiceURL != "" {
		return c.ServiceURL
	}
	return "https://api.virgilsecurity.com"
}

func (c *CardClient) getHttpClient() common.HttpClient {
	if c.HttpClient != nil {
		return c.HttpClient
	}
	return http.DefaultClient
}

func (c *CardClient) getVirgilClient() *common.VirgilHttpClient {

	c.once.Do(func() {
		if c.VirgilHttpClient == nil {
			c.VirgilHttpClient = &common.VirgilHttpClient{
				Address: c.getUrl(),
				Client:  c.getHttpClient(),
			}
		}
	})

	return c.VirgilHttpClient
}
