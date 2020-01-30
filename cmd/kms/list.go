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

package kms

import (
	"fmt"
	"net/http"

	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/cmd/kms/protobuf/decryptor"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

func List(vcli *client.VirgilHTTPClient) *cli.Command {
	return &cli.Command{
		Name:    "list",
		Aliases: []string{"l"},
		Usage:   "List your KMS keys",
		Action: func(context *cli.Context) (err error) {
			defaultApp, _ := utils.LoadDefaultApp()
			defaultAppToken := ""
			if defaultApp != nil {
				defaultAppToken = defaultApp.Token
			}

			appToken := utils.ReadFlagOrDefault(context, "app-token", defaultAppToken)
			if appToken == "" {
				return errors.New("Please, specify app-token (flag --app-token)")
			}

			keyPairs, err := listFunc(appToken, vcli)

			fmt.Printf("|%25s|%35s|%20s\n", "Keypair alias   ", "Keypair version   ", " Public Key ")
			fmt.Printf("|%25s|%35s|%20s\n", "-------------------------", "-----------------------------------", "---------------------------------------")
			for _, keyPair := range keyPairs {
				fmt.Printf(
					"| %23s | %33d | %19s\n",
					keyPair.Alias,
					int(keyPair.KeyVersion),
					recoveryKeyChecker(keyPair),
				)
			}
			return nil
		},
	}
}

func listFunc(appToken string, vcli *client.VirgilHTTPClient) (keyPairs []*decryptor.Keypair, err error) {
	var resp []byte
	_, _, err = utils.SendProtoWithCheckRetry(vcli, http.MethodPost, "kms/v1/search-keypairs", nil, &resp, appToken)

	protoKeyPairs := &decryptor.Keypairs{}
	if err := proto.Unmarshal(resp, protoKeyPairs); err != nil {
		return nil, err
	}

	keyPairs = protoKeyPairs.Keypairs

	if err != nil {
		return
	}

	if keyPairs != nil {
		return keyPairs, nil
	}

	return nil, errors.New("empty response")
}
