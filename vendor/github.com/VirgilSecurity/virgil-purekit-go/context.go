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
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/VirgilSecurity/virgil-phe-go"

	"github.com/pkg/errors"
)

// Context holds & validates protocol input parameters
type Context struct {
	AppToken    string
	PHEClients  map[uint32]*phe.Client
	Version     uint32
	UpdateToken *VersionedUpdateToken
}

//CreateContext validates input parameters and prepares them for being used in Protocol
func CreateContext(appToken, servicePublicKey, clientSecretKey, updateToken string) (*Context, error) {

	if appToken == "" {
		return nil, errors.New("app token is mandatory")
	}

	skVersion, sk, err := ParseVersionAndContent("SK", clientSecretKey)
	if err != nil {
		return nil, errors.Wrap(err, "invalid secret key")
	}

	pubVersion, pubBytes, err := ParseVersionAndContent("PK", servicePublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "invalid public key")
	}

	if skVersion != pubVersion {
		return nil, errors.New("public and secret keys must have the same version")
	}

	currentSk, currentPub := sk, pubBytes
	pheClient, err := phe.NewClient(currentPub, currentSk)

	if err != nil {
		return nil, errors.Wrap(err, "could not create PHE client")
	}

	phes := make(map[uint32]*phe.Client)
	phes[pubVersion] = pheClient

	token, err := parseToken(updateToken)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse update tokens")
	}

	currentVersion := pubVersion

	if token != nil {
		curVer, err := processToken(token, phes, currentVersion, currentPub, currentSk)
		if err != nil {
			return nil, err
		}
		currentVersion = curVer
	}

	return &Context{
		AppToken:    appToken,
		PHEClients:  phes,
		Version:     currentVersion,
		UpdateToken: token,
	}, nil
}

func processToken(token *VersionedUpdateToken, clients map[uint32]*phe.Client, curVer uint32, currentPub, currentSk []byte) (currentVersion uint32, err error) {
	if token.Version != curVer+1 {
		return 0, fmt.Errorf("incorrect token version %d", token.Version)
	}

	nextSk, nextPub, err := phe.RotateClientKeys(currentPub, currentSk, token.UpdateToken)
	if err != nil {
		return 0, errors.Wrap(err, "could not update keys using token")
	}

	nextClient, err := phe.NewClient(nextPub, nextSk)
	if err != nil {
		return 0, errors.Wrap(err, "could not create PHE client")
	}

	clients[token.Version] = nextClient
	currentVersion = token.Version
	return
}

func parseToken(token string) (parsedToken *VersionedUpdateToken, err error) {
	if len(token) == 0 {
		return nil, nil
	}

	version, content, err := ParseVersionAndContent("UT", token)

	if err != nil {
		return nil, errors.Wrap(err, "invalid update token")
	}

	vt := &VersionedUpdateToken{
		Version:     version,
		UpdateToken: content,
	}

	parsedToken = vt

	return parsedToken, nil
}

//ParseVersionAndContent splits string into 3 parts: Prefix, version and decoded base64 content
func ParseVersionAndContent(prefix, str string) (version uint32, content []byte, err error) {
	parts := strings.Split(str, ".")
	if len(parts) != 3 || parts[0] != prefix {
		return 0, nil, errors.New("invalid string")
	}

	nVersion, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, nil, errors.Wrap(err, "invalid string")
	}

	if nVersion < 1 {
		return 0, nil, errors.Wrap(err, "invalid version")
	}
	version = uint32(nVersion)

	content, err = base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return 0, nil, errors.Wrap(err, "invalid string")
	}
	return
}
