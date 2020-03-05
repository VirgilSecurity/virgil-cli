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
	"io/ioutil"

	"github.com/urfave/cli/v2"
	"gopkg.in/virgil.v5/cryptoimpl"

	"github.com/VirgilSecurity/virgil-cli/utils"
)

func Verify() *cli.Command {
	return &cli.Command{
		Name:      "verify",
		ArgsUsage: "[pub_key]",
		Usage:     "Verify signature",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "key", Usage: "public key file"},
			&cli.StringFlag{Name: "i", Usage: "input file"},
			&cli.StringFlag{Name: "s", Usage: "signature file"},
		},
		Action: func(context *cli.Context) error {
			keyFileName := utils.ReadFlagOrDefault(context, "key", "")
			if keyFileName == "" {
				return utils.CliExit(errors.New(utils.KeyFileNotSpecified))
			}
			inputFileName := utils.ReadFlagOrDefault(context, "i", "")
			if inputFileName == "" {
				return utils.CliExit(errors.New(utils.InputFileNotSpecified))
			}
			signatureFileName := utils.ReadFlagOrDefault(context, "s", "")
			if signatureFileName == "" {
				return utils.CliExit(errors.New(utils.SignatureFileNotSpecified))
			}
			publicKeyString, err := utils.ReadKeyStringFromFile(context, keyFileName)
			if err != nil {
				return utils.CliExit(err)
			}

			data, err := ioutil.ReadFile(inputFileName)
			if err != nil {
				return utils.CliExit(err)
			}

			signature, err := ioutil.ReadFile(signatureFileName)
			if err != nil {
				return utils.CliExit(err)
			}

			err = VerifyFunc(publicKeyString, data, signature)

			if err != nil {
				return utils.CliExit(err)
			}

			fmt.Println(utils.VerifySuccess)
			return nil
		},
	}
}

func VerifyFunc(publicKeyString string, data, signature []byte) (err error) {
	pk, err := cryptoimpl.DecodePublicKey([]byte(publicKeyString))

	if err != nil {
		return errors.New(utils.CantImportPublicKey)
	}

	ss, err := base64.StdEncoding.DecodeString(string(signature))

	if err != nil {
		return err
	}

	err = crypto.VerifySignature(data, ss, pk)
	if err != nil {
		return errors.New(utils.VerifyFailed)
	}

	return nil
}
