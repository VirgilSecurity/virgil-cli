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

package pure

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto/wrapper/phe"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	"github.com/VirgilSecurity/virgil-cli/cmd/kms"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

const (
	OldKeyPartsCount = 3
)

// UpdateKeys updates secret key and public key using update token
func UpdateKeys() *cli.Command {
	return &cli.Command{
		Name:      "update-keys",
		Aliases:   []string{"u"},
		ArgsUsage: "public_key service_secret_key update_token",
		Usage:     "update secret key and public key using update token",
		Action:    updateFunc,
	}
}
func updateFunc(context *cli.Context) error {
	if context.NArg() < OldKeyPartsCount {
		return errors.New("invalid number of arguments")
	}

	pkStr := context.Args().First()
	skStr := context.Args().Get(1)
	tokenStr := context.Args().Get(2)

	if isNewKeysVersion(pkStr, skStr, tokenStr) {
		return rotate(pkStr, skStr, tokenStr)
	} else {
		return oldRotate(pkStr, skStr, tokenStr)
	}
}

func isNewKeysVersion(pkStr, skStr, tokenStr string) bool {
	pkPartsCount := len(strings.Split(pkStr, "."))
	skPartsCount := len(strings.Split(skStr, "."))
	tokenPartsCount := len(strings.Split(tokenStr, "."))

	return pkPartsCount > OldKeyPartsCount && skPartsCount > OldKeyPartsCount && tokenPartsCount > OldKeyPartsCount
}

func oldRotate(pkStr, skStr, tokenStr string) error {
	pkVersion, pk, err := utils.ParseVersionAndContent("PK", pkStr)
	if err != nil {
		return errors.Wrapf(err, "parse public key failed: ")
	}
	skVersion, sk, err := utils.ParseVersionAndContent("SK", skStr)
	if err != nil {
		return errors.Wrapf(err, "parse private key failed: ")
	}
	tokenVersion, updateToken, err := utils.ParseVersionAndContent("UT", tokenStr)

	if err != nil {
		return errors.Wrapf(err, "parse update token failed: ")
	}

	if (pkVersion+1) != tokenVersion || (skVersion+1) != tokenVersion {
		return errors.New("Key version must be 1 less than token version")
	}

	pheClient := phe.NewPheClient()
	if err := pheClient.SetKeys(sk, pk); err != nil {
		return err
	}
	if err := pheClient.SetupDefaults(); err != nil {
		return err
	}
	newSk, newPk, err := pheClient.RotateKeys(updateToken)
	if err != nil {
		return err
	}

	fmt.Printf("New server public key:\nPK.%d.%s\nNew client private key:\nSK.%d.%s\n",
		tokenVersion, base64.StdEncoding.EncodeToString(newPk),
		tokenVersion, base64.StdEncoding.EncodeToString(newSk),
	)
	return nil
}

func rotate(pkStr, skStr, tokenStr string) error {
	pkVersion, pkPhe, pkKMS, _, err := utils.ParseCombinedEntities("PK", pkStr)
	if err != nil {
		return errors.Wrapf(err, "parse public key failed: ")
	}
	skVersion, skPhe, skKMS, skAuth, err := utils.ParseCombinedEntities("SK", skStr)
	if err != nil {
		return errors.Wrapf(err, "parse private key failed: ")
	}
	tokenVersion, updateTokenPhe, updateTokenKMS, updateTokenAuth, err := utils.ParseCombinedEntities("UT", tokenStr)

	if err != nil {
		return errors.Wrapf(err, "parse update token failed: ")
	}

	if (pkVersion+1) != tokenVersion || (skVersion+1) != tokenVersion {
		return errors.New("Key version must be 1 less than token version")
	}

	pheClient := phe.NewPheClient()
	if err := pheClient.SetKeys(skPhe, pkPhe); err != nil {
		return err
	}
	if err := pheClient.SetupDefaults(); err != nil {
		return err
	}
	newPheSk, newPhePk, err := pheClient.RotateKeys(updateTokenPhe)
	if err != nil {
		return err
	}

	newKMSSk, newKMSPk, err := kms.RotateKMSKeys(skKMS, pkKMS, updateTokenKMS)
	if err != nil {
		return err
	}

	uokmsClient := phe.NewUokmsClient()
	if err := uokmsClient.SetKeysOneparty(skAuth); err != nil {
		return err
	}
	newSkAuth, err := uokmsClient.RotateKeysOneparty(updateTokenAuth)
	if err != nil {
		return err
	}

	fmt.Printf("New server public key:\nPK.%d.%s.%s\nNew client private key:\nSK.%d.%s.%s.%s\n",
		tokenVersion,
		base64.StdEncoding.EncodeToString(newPhePk),
		base64.StdEncoding.EncodeToString(newKMSPk),
		tokenVersion,
		base64.StdEncoding.EncodeToString(newPheSk),
		base64.StdEncoding.EncodeToString(newKMSSk),
		base64.StdEncoding.EncodeToString(newSkAuth),
	)
	return nil
}
