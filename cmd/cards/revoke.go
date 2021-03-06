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
package cards

import (
	"fmt"
	"io/ioutil"
	"time"

	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto"
	"github.com/VirgilSecurity/virgil-sdk-go/v6/sdk"
	"github.com/VirgilSecurity/virgil-sdk-go/v6/session"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	"github.com/VirgilSecurity/virgil-cli/utils"
)

var crypt = &crypto.Crypto{}

func Revoke() *cli.Command {
	return &cli.Command{
		Name:      "revoke",
		ArgsUsage: "[id]",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "c", Usage: "config file name"},
			&cli.StringFlag{Name: "i", Usage: "identity"},
		},
		Usage: "delete cards by id",
		Action: func(context *cli.Context) error {
			cardID := utils.ReadParamOrDefaultOrFromConsole(context, "id", utils.CardIDPrompt, "")

			configFileName := utils.ReadFlagOrDefault(context, "c", "")
			if configFileName == "" {
				return utils.CliExit(errors.New(utils.ConfigurationFileNotSpecified))
			}

			data, err := ioutil.ReadFile(configFileName)
			if err != nil {
				fmt.Print(err)
			}

			conf, err := utils.ParseAppConfig(data)
			if err != nil {
				fmt.Print(err)
			}

			privateKey, err := crypt.ImportPrivateKey(conf.APPKey)
			if err != nil {
				return utils.CliExit(err)
			}

			identity := utils.ReadFlagOrConsoleValue(context, "i", utils.CardIdentityPrompt)

			generator := session.JwtGenerator{
				AppKey:            privateKey,
				AppKeyID:          conf.APPKeyID,
				AppID:             conf.AppID,
				AccessTokenSigner: &session.VirgilAccessTokenSigner{Crypto: crypt},
				TTL:               time.Minute,
			}

			cardManager := sdk.NewCardManager(session.NewGeneratorJwtProvider(generator, session.SetGeneratorJwtProviderDefaultIdentity(identity)))
			yesOrNo := utils.ReadConsoleValue("y or n", fmt.Sprintf("%s (y/n) ?", utils.CardDeletePrompt), "y", "n")
			if yesOrNo == "n" {
				return nil
			}

			err = cardManager.RevokeCard(cardID)

			if err == utils.ErrEntityNotFound {
				return utils.CliExit(errors.New(fmt.Sprintf("%s %s \n", utils.CardNotFound, cardID)))
			}
			if err != nil {
				return utils.CliExit(err)
			}
			fmt.Println(utils.CardDeleteSuccess)

			return nil
		},
	}
}
