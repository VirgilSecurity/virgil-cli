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

	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto/wrapper/phe"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	"github.com/VirgilSecurity/virgil-cli/cmd/pure/keygen"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

// Keygen generates PureKit private key
func Keygen() *cli.Command {
	return &cli.Command{
		Name:    "keygen",
		Aliases: []string{"kg"},
		Usage:   "Generate a new Pure secret key",
		Action: func(context *cli.Context) error {
			if context.Args().First() != "" {
				return utils.CliExit(errors.New("incorrect key type"))
			}
			pheClient := phe.NewPheClient()
			if err := pheClient.SetupDefaults(); err != nil {
				return utils.CliExit(err)
			}
			key, err := pheClient.GenerateClientPrivateKey()
			if err != nil {
				return utils.CliExit(err)
			}
			fmt.Println("SK.1." + base64.StdEncoding.EncodeToString(key))
			return nil
		},
		Subcommands: []*cli.Command{
			keygen.Secret(),
			keygen.Auth(),
			keygen.Backup(),
			keygen.VirgilStorage(),
			keygen.OwnSigningKey(),
			keygen.All(),
			keygen.NonRotatableMasterSecret(),
		},
	}
}
