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
	"time"

	"gopkg.in/virgil.v5/cryptoapi"
	"gopkg.in/virgil.v5/errors"
)

type JwtGenerator struct {
	ApiKey                 cryptoapi.PrivateKey
	ApiPublicKeyIdentifier string
	AccessTokenSigner      cryptoapi.AccessTokenSigner
	AppId                  string
	TTL                    time.Duration
}

func NewJwtGenerator(apiKey cryptoapi.PrivateKey, apiPublicKeyIdentifier string, signer cryptoapi.AccessTokenSigner, appId string, ttl time.Duration) *JwtGenerator {

	return &JwtGenerator{
		AppId:                  appId,
		AccessTokenSigner:      signer,
		TTL:                    ttl,
		ApiKey:                 apiKey,
		ApiPublicKeyIdentifier: apiPublicKeyIdentifier,
	}
}

func (j *JwtGenerator) GenerateToken(identity string, additionalData map[string]interface{}) (*Jwt, error) {

	if j.ApiKey == nil {
		return nil, errors.New("Api private key is not set")
	}

	if j.AccessTokenSigner == nil {
		return nil, errors.New("AccessTokenSigner is not set")
	}

	if SpaceMap(identity) == "" {
		return nil, errors.New("identity is mandatory")
	}

	issuedAt := time.Now().UTC().Truncate(time.Second)
	expiresAt := issuedAt.Add(j.TTL)
	jwtBody, err := NewJwtBodyContent(j.AppId, identity, issuedAt, expiresAt, additionalData)

	if err != nil {
		return nil, err
	}

	jwtHeader, err := NewJwtHeaderContent(j.AccessTokenSigner.GetAlgorithm(), j.ApiPublicKeyIdentifier)
	if err != nil {
		return nil, err
	}

	unsignedJwt, err := NewJwt(jwtHeader, jwtBody, nil)
	if err != nil {
		return nil, err
	}
	jwtSignature, err := j.AccessTokenSigner.GenerateTokenSignature(unsignedJwt.Unsigned(), j.ApiKey)
	if err != nil {
		return nil, err
	}

	return NewJwt(jwtHeader, jwtBody, jwtSignature)
}
