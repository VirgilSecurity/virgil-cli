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
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/urfave/cli/v2"

	"github.com/VirgilSecurity/virgil-cli/utils"
)

func Decrypt() *cli.Command {
	return &cli.Command{
		Name:      "decrypt",
		ArgsUsage: "[inp]",
		Usage:     "Decrypt data",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "o", Usage: "destination file name"},
			&cli.StringFlag{Name: "key", Usage: "private key file"},
			&cli.StringFlag{Name: "i", Usage: "input file"},
		},
		Action: func(context *cli.Context) error {
			destinationFileName := utils.ReadFlagOrDefault(context, "o", "")
			keyFileName := utils.ReadFlagOrDefault(context, "key", "")
			if keyFileName == "" {
				return utils.CliExit(errors.New(utils.KeyFileNotSpecified))
			}

			dataToDecrypt, err := utils.ReadFileFlagOrParamOrFromConsole(context, "i", "inp", utils.DecryptDataPrompt)
			if err != nil {
				return utils.CliExit(err)
			}

			privateKeyString, err := utils.ReadKeyStringFromFile(context, keyFileName)
			if err != nil {
				return utils.CliExit(err)
			}

			var writer io.Writer = os.Stdout
			if destinationFileName != "" {
				var file *os.File
				file, err = os.Create(destinationFileName)
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

			key, err := DecryptFunc(privateKeyString, dataToDecrypt)
			if err != nil {
				return utils.CliExit(err)
			}

			_, err = fmt.Fprint(writer, string(key))
			if err != nil {
				return utils.CliExit(err)
			}
			fmt.Println()

			return nil
		},
	}
}

func DecryptFunc(privateKeyString string, data []byte) (publicKey []byte, err error) {
	pk, err := crypt.ImportPrivateKey([]byte(privateKeyString))

	if err != nil {
		return nil, errors.New(utils.CantImportPrivateKey)
	}

	dd, err := base64.StdEncoding.DecodeString(string(data))

	if err != nil {
		return nil, err
	}

	return crypt.Decrypt(dd, pk)
}
