/*
 * Copyright (C) 2015-2020 Virgil Security Inc.
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
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// ParseVersionAndContent splits string into 3 parts: Prefix, version and decoded base64 content
func ParseVersionAndContent(prefix, str string) (version uint32, content []byte, err error) {
	parts := strings.Split(str, ".")
	if len(parts) != 3 {
		return 0, nil, errors.New("invalid string: wrong number of blocks")
	}

	if parts[0] != prefix {
		return 0, nil, errors.New("invalid string: wrong prefix")
	}

	nVersion, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, nil, errors.Wrap(err, "invalid string: malformed version part")
	}

	if nVersion < 1 {
		return 0, nil, errors.Wrap(err, "invalid version")
	}
	version = uint32(nVersion)

	content, err = base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return 0, nil, errors.Wrap(err, "invalid string: malformed data")
	}
	return
}

// ParseCombinedEntities splits string into 4 parts: Prefix, version and decoded base64 content Phe and Kms keys
func ParseCombinedEntities(prefix, combinedEntity string) (version uint32, pheKeyContent, kmsKeyContent, authKeyContent []byte, err error) {
	parts := strings.Split(combinedEntity, ".")
	switch {
	case len(parts) != 5 && prefix != "PK":
		return 0, nil, nil, nil, errors.New("invalid string: wrong number of blocks")
	case len(parts) != 4 && prefix == "PK":
		return 0, nil, nil, nil, errors.New("invalid string: wrong number of blocks")
	}

	if parts[0] != prefix {
		return 0, nil, nil, nil, errors.New("invalid string: wrong prefix")
	}

	nVersion, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, nil, nil, nil, errors.Wrap(err, "invalid string: malformed version part")
	}

	if nVersion < 1 {
		return 0, nil, nil, nil, errors.Wrap(err, "invalid version")
	}
	version = uint32(nVersion)

	pheKeyContent, err = base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return 0, nil, nil, nil, errors.Wrap(err, "invalid string: malformed first data part")
	}

	kmsKeyContent, err = base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return 0, nil, nil, nil, errors.Wrap(err, "invalid string: malformed second data part")
	}

	if prefix != "PK" {
		authKeyContent, err = base64.StdEncoding.DecodeString(parts[4])
		if err != nil {
			return 0, nil, nil, nil, errors.Wrap(err, "invalid string: malformed third data part")
		}
	}
	return
}
