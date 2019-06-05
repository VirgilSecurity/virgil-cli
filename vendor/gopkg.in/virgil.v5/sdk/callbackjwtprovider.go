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

import "gopkg.in/virgil.v5/errors"

type CallbackJwtProvider struct {
	GetTokenCallback func(context *TokenContext) (*Jwt, error)
}

func NewCallbackJwtProvider(callback func(context *TokenContext) (*Jwt, error)) AccessTokenProvider {
	return &CallbackJwtProvider{
		GetTokenCallback: callback,
	}
}

func NewCallbackStringJwtProvider(renewTokenCallback func(context *TokenContext) (string, error)) *CallbackJwtProvider {
	return &CallbackJwtProvider{
		GetTokenCallback: func(context *TokenContext) (*Jwt, error) {
			token, err := renewTokenCallback(context)
			if err != nil {
				return nil, err
			}
			return JwtFromString(token)
		},
	}
}

func (c *CallbackJwtProvider) GetToken(context *TokenContext) (AccessToken, error) {
	if c.GetTokenCallback == nil {
		return nil, errors.New("GetTokenCallback must be set")
	}
	if context == nil {
		return nil, errors.New("context is mandatory")
	}

	if jwt, err := c.GetTokenCallback(context); err != nil {
		return nil, err
	} else {
		return jwt, nil
	}
}
