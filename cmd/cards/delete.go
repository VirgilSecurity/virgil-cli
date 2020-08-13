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

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"gopkg.in/virgil.v5/sdk"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

func Revoke(vcli *client.VirgilHTTPClient) *cli.Command {
	return &cli.Command{
		Name:      "revoke",
		ArgsUsage: "[id]",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "c", Usage: "private key password"},
			&cli.StringFlag{Name: "i", Usage: "config file name"},
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

			privateKey, err := crypto.ImportPrivateKey(conf.APPKey, "")
			if err != nil {
				return utils.CliExit(err)
			}

			identity := utils.ReadFlagOrConsoleValue(context, "i", utils.CardIdentityPrompt)

			ttl := time.Minute

			jwtGenerator := sdk.NewJwtGenerator(privateKey, conf.APPKeyID, tokenSigner, conf.AppID, ttl)
			cardVerifier, err := sdk.NewVirgilCardVerifier(cardCrypto, true, true)
			if err != nil {
				return utils.CliExit(err)
			}
			mgrParams := &sdk.CardManagerParams{
				Crypto:              cardCrypto,
				CardVerifier:        cardVerifier,
				AccessTokenProvider: sdk.NewGeneratorJwtProvider(jwtGenerator, nil, identity),
			}

			cardManager, err := sdk.NewCardManager(mgrParams)
			if err != nil {
				return utils.CliExit(err)
			}
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
