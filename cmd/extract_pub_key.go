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
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/urfave/cli/v2"
	"gopkg.in/virgil.v5/cryptoimpl"

	"github.com/VirgilSecurity/virgil-cli/utils"
)

func Key2Pub() *cli.Command {
	return &cli.Command{
		Name:      "key2pub",
		ArgsUsage: "[prKey]",
		Usage:     "Extract public key",
		Flags: []cli.Flag{&cli.StringFlag{Name: "o", Usage: "destination file name"},
			&cli.StringFlag{Name: "p", Usage: "password"},
			&cli.StringFlag{Name: "i", Usage: "input file"},
		},
		Action: func(context *cli.Context) error {
			pass := utils.ReadFlagOrDefault(context, "p", "")

			destinationFileName := utils.ReadFlagOrDefault(context, "o", "")
			inputFileName := utils.ReadFlagOrDefault(context, "i", "")

			privateKeyString := ""
			if inputFileName != "" {
				f, err := os.Open(inputFileName)
				if err != nil {
					return utils.CliExit(err)
				}
				defer func() {
					if err := f.Close(); err != nil {
						panic(err)
					}
				}()

				scanner := bufio.NewScanner(f)
				for scanner.Scan() {
					t := scanner.Text()
					if strings.Contains(t, "BEGIN ") {
						continue
					}
					privateKeyString = t
					break
				}
			} else {
				privateKeyString = utils.ReadParamOrDefaultOrFromConsole(context, "prKey", "private key", "")
			}

			var writer io.Writer
			if destinationFileName != "" {
				file, err := os.Create(destinationFileName)
				if err != nil {
					return utils.CliExit(err)
				}
				writer = file
				defer func() {
					if err := file.Close(); err != nil {
						panic(err)
					}
				}()
			} else {
				writer = os.Stdout
			}
			key, err := Key2PubFunc(privateKeyString, pass)

			if err != nil {
				return utils.CliExit(err)
			}

			_, err = fmt.Fprintf(writer, "-----BEGIN PUBLIC KEY-----\n")
			if err != nil {
				return utils.CliExit(err)
			}
			_, err = fmt.Fprintln(writer, base64.StdEncoding.EncodeToString(key))
			if err != nil {
				return utils.CliExit(err)
			}
			_, err = fmt.Fprintf(writer, "-----END PUBLIC KEY-----\n")
			if err != nil {
				return utils.CliExit(err)
			}

			return err
		},
	}
}

func Key2PubFunc(privateKeyString, password string) (publicKey []byte, err error) {
	pk, err := cryptoimpl.DecodePrivateKey([]byte(privateKeyString), []byte(password))

	if err != nil {
		return nil, fmt.Errorf(utils.ExtractPubKeyParseFailed)
	}

	pubKey, err := pk.ExtractPublicKey()
	if err != nil {
		return nil, err
	}

	return pubKey.Encode()
}
