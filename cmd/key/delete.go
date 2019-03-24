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

package key

import (
	"fmt"
	"net/http"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/utils"
	"github.com/pkg/errors"
	"gopkg.in/urfave/cli.v2"
)

func Delete(vcli *client.VirgilHttpClient) *cli.Command {
	return &cli.Command{
		Name:      "delete-api-key",
		Aliases:   []string{"delete", "d"},
		ArgsUsage: "api-key_id",
		Usage:     "Deletes the api key by id",
		Flags:     []cli.Flag{&cli.StringFlag{Name: "app_id"}},
		Action: func(context *cli.Context) (err error) {

			apiKeyID := utils.ReadParamOrDefaultOrFromConsole(context, "id", "api-key id", "")

			err = deleteApiKeyIDFunc(apiKeyID, vcli)

			if err == nil {
				fmt.Println("Api key delete ok.")
			} else if err == utils.ErrEntityNotFound {
				return errors.New(fmt.Sprintf("Api key with id %s not found.\n", apiKeyID))
			}

			return err
		},
	}
}

func deleteApiKeyIDFunc(apiKeyID string, vcli *client.VirgilHttpClient) (err error) {

	_, _, err = utils.SendWithCheckRetry(vcli, http.MethodDelete, "access_keys/"+apiKeyID, nil, nil)

	return err
}
