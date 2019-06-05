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

	"strings"

	"encoding/base64"

	"encoding/json"

	"gopkg.in/virgil.v5/errors"
)

type Jwt struct {
	BodyContent      *JwtBodyContent
	bodyBytes        []byte
	HeaderContent    *JwtHeaderContent
	headerBytes      []byte
	SignatureContent []byte
	StringContents   string
	unsigned         []byte
}

func NewJwt(header *JwtHeaderContent, body *JwtBodyContent, signature []byte) (*Jwt, error) {
	if header == nil {
		return nil, errors.New("header is mandatory")
	}
	if body == nil {
		return nil, errors.New("body is mandatory")
	}

	jwt := &Jwt{
		HeaderContent:    header,
		BodyContent:      body,
		SignatureContent: signature,
	}

	headerStr, err := jwt.HeaderBase64()
	if err != nil {
		return nil, err
	}
	bodyStr, err := jwt.BodyBase64()
	if err != nil {
		return nil, err
	}
	jwt.unsigned = []byte(headerStr + "." + bodyStr)
	jwt.StringContents = headerStr + "." + bodyStr
	if signature != nil {
		jwt.StringContents += "." + jwt.SignatureBase64()
	}
	return jwt, nil

}

func JwtFromString(token string) (*Jwt, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("JWT parse failed")
	}

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.Wrap(err, "JWT header parsing")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.Wrap(err, "JWT body parsing")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.Wrap(err, "JWT signature parsing")
	}

	var headerContent *JwtHeaderContent
	if err := json.Unmarshal(header, &headerContent); err != nil {
		return nil, errors.Wrap(err, "JWT header parsing")
	}

	var bodyContent *JwtBodyContent
	if err := json.Unmarshal(body, &bodyContent); err != nil {
		return nil, errors.Wrap(err, "JWT body parsing")
	}

	if !strings.Contains(bodyContent.Issuer, IssuerPrefix) || !strings.Contains(bodyContent.Subject, IdentityPrefix) {
		return nil, errors.New("JWT body does not contain virgil prefix")
	}

	bodyContent.AppID = strings.TrimPrefix(bodyContent.Issuer, IssuerPrefix)
	bodyContent.Identity = strings.TrimPrefix(bodyContent.Subject, IdentityPrefix)

	return &Jwt{
		BodyContent:      bodyContent,
		HeaderContent:    headerContent,
		SignatureContent: signature,
		StringContents:   token,
		bodyBytes:        body,
		headerBytes:      header,
		unsigned:         []byte(parts[0] + "." + parts[1]),
	}, nil
}

func (j *Jwt) String() string {
	return j.StringContents
}

func (j *Jwt) Identity() (string, error) {

	if j.BodyContent == nil {
		return "", errors.New("header content is empty")
	}

	return j.BodyContent.Identity, nil
}

func (j *Jwt) IsExpired() error {

	return j.IsExpiredDelta(0)
}

//IsExpiredDelta returns error if token expires delta time before it's expiry date
func (j *Jwt) IsExpiredDelta(delta time.Duration) error {
	if j.BodyContent == nil {
		return errors.New("header content is empty")
	}

	exp := time.Unix(j.BodyContent.ExpiresAt, 0).Add(-delta)
	now := time.Now()

	if exp.Before(now) {
		return errors.New("JWT token is expired")
	}
	return nil
}

func (j *Jwt) Unsigned() []byte {
	return j.unsigned
}

func (j *Jwt) HeaderBase64() (string, error) {
	if j.headerBytes == nil {
		if headerBytes, err := json.Marshal(j.HeaderContent); err != nil {
			return "", err
		} else {
			j.headerBytes = headerBytes
		}
	}
	return base64.RawURLEncoding.EncodeToString(j.headerBytes), nil
}

func (j *Jwt) BodyBase64() (string, error) {
	if j.bodyBytes == nil {
		if bodyBytes, err := json.Marshal(j.BodyContent); err != nil {
			return "", err
		} else {
			j.bodyBytes = bodyBytes
		}
	}
	return base64.RawURLEncoding.EncodeToString(j.bodyBytes), nil
}

func (j *Jwt) SignatureBase64() string {
	return base64.RawURLEncoding.EncodeToString(j.SignatureContent)
}
