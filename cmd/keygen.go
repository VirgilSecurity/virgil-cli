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
package cmd

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/urfave/cli/v2"

	"github.com/VirgilSecurity/virgil-cli/utils"
)

func Keygen() *cli.Command {
	return &cli.Command{
		Name:  "keygen",
		Usage: "Generate keypair",
		Flags: []cli.Flag{&cli.StringFlag{Name: "o", Usage: "destination file name"}},
		Action: func(context *cli.Context) error {
			pass := utils.ReadFlagOrDefault(context, "p", "")
			key, err := KeygenFunc()
			if err != nil {
				return utils.CliExit(err)
			}

			var writer io.Writer = os.Stdout
			if fileName := utils.ReadFlagOrDefault(context, "o", ""); fileName != "" {
				var file *os.File
				file, err = os.Create(fileName)
				if err != nil {
					return utils.CliExit(err)
				}
				defer func() {
					if ferr := file.Close(); ferr != nil {
						panic(ferr)
					}
				}()

				writer = file
			}

			encrypted := " "
			if pass != "" {
				encrypted = " ENCRYPTED "
			}

			_, err = fmt.Fprintf(writer, "-----BEGIN%sPRIVATE KEY-----\n", encrypted)
			if err != nil {
				return utils.CliExit(err)
			}
			_, err = fmt.Fprintln(writer, base64.StdEncoding.EncodeToString(key))
			if err != nil {
				return utils.CliExit(err)
			}
			_, err = fmt.Fprintf(writer, "-----END%sPRIVATE KEY-----\n", encrypted)

			if err != nil {
				return utils.CliExit(err)
			}

			return err
		},
	}
}

func KeygenFunc() (privateKey []byte, err error) {
	keyPair, err := crypt.GenerateKeypair()

	if err != nil {
		return nil, err
	}

	return crypt.ExportPrivateKey(keyPair)
}
