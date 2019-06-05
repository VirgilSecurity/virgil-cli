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
	"gopkg.in/virgil.v5/cryptoapi"
	"gopkg.in/virgil.v5/errors"
)

type JwtVerifier struct {
	ApiPublicKey      cryptoapi.PublicKey
	ApiPublicKeyId    string
	AccessTokenSigner cryptoapi.AccessTokenSigner
}

func NewJwtVerifier(apiPublicKey cryptoapi.PublicKey, apiPublicKeyId string, accessTokenSigner cryptoapi.AccessTokenSigner) *JwtVerifier {
	return &JwtVerifier{
		AccessTokenSigner: accessTokenSigner,
		ApiPublicKeyId:    apiPublicKeyId,
		ApiPublicKey:      apiPublicKey,
	}
}

func (j *JwtVerifier) VerifyToken(jwtToken *Jwt) error {
	if j.AccessTokenSigner == nil {
		return errors.New("AccessTokenSigner is not set")
	}

	if j.ApiPublicKey == nil {
		return errors.New("ApiPublicKey is not set")
	}

	if SpaceMap(j.ApiPublicKeyId) == "" {
		return errors.New("ApiPublicKeyId is not set")
	}

	if jwtToken == nil {
		return errors.New("jwtToken is mandatory")
	}

	if jwtToken.HeaderContent.ApiKeyId != j.ApiPublicKeyId ||
		jwtToken.HeaderContent.Algorithm != j.AccessTokenSigner.GetAlgorithm() ||
		jwtToken.HeaderContent.ContentType != VirgilContentType ||
		jwtToken.HeaderContent.Type != JwtType {
		return errors.New("JWT is not valid")
	}

	return j.AccessTokenSigner.VerifyTokenSignature(jwtToken.Unsigned(), jwtToken.SignatureContent, j.ApiPublicKey)
}
