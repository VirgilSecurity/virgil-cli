/*
 * Copyright (C) 2015-2018 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   (1) Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   (2) Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 *   (3) Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
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
 */

package sdk

import (
	"fmt"

	"gopkg.in/virgil.v5/cryptoapi"
	"gopkg.in/virgil.v5/errors"
)

const (
	SelfSigner   = "self"
	VirgilSigner = "virgil"
)

type ModelSigner struct {
	Crypto cryptoapi.CardCrypto
}

func NewModelSigner(crypto cryptoapi.CardCrypto) *ModelSigner {
	return &ModelSigner{Crypto: crypto}
}

func (m *ModelSigner) Sign(model *RawSignedModel, signer string, privateKey cryptoapi.PrivateKey, extraFields map[string]string) (err error) {
	var extraFieldsSnapshot []byte
	if extraFields != nil {
		extraFieldsSnapshot, err = TakeSnapshot(extraFields)
		if err != nil {
			return err
		}
	}

	return m.signInternal(model, &SignParams{
		SignerPrivateKey: privateKey,
		Signer:           signer,
	}, extraFieldsSnapshot)
}

func (m *ModelSigner) SignRaw(model *RawSignedModel, signer string, privateKey cryptoapi.PrivateKey, extraFieldsSnapshot []byte) (err error) {

	return m.signInternal(model, &SignParams{
		SignerPrivateKey: privateKey,
		Signer:           signer,
	}, extraFieldsSnapshot)
}

func (m *ModelSigner) SelfSign(model *RawSignedModel, privateKey cryptoapi.PrivateKey, extraFields map[string]string) (err error) {
	var extraFieldsSnapshot []byte
	if extraFields != nil {
		extraFieldsSnapshot, err = TakeSnapshot(extraFields)
		if err != nil {
			return err
		}
	}

	return m.signInternal(model, &SignParams{
		SignerPrivateKey: privateKey,
		Signer:           SelfSigner,
	}, extraFieldsSnapshot)
}

func (m *ModelSigner) SelfSignRaw(model *RawSignedModel, privateKey cryptoapi.PrivateKey, extraFieldsSnapshot []byte) (err error) {
	return m.signInternal(model, &SignParams{
		SignerPrivateKey: privateKey,
		Signer:           SelfSigner,
	}, extraFieldsSnapshot)
}

func (m *ModelSigner) signInternal(model *RawSignedModel, params *SignParams, extraFieldsSnapshot []byte) error {
	if model == nil {
		return errors.New("model is mandatory")
	}
	if m.Crypto == nil {
		return errors.New("crypto is mandatory")
	}
	var err error
	if err = params.Validate(); err != nil {
		return err
	}

	err = m.CheckSignatureExists(model, params)
	if err != nil {
		return err
	}

	resultSnapshot := append(model.ContentSnapshot, extraFieldsSnapshot...)
	signature, err := m.Crypto.GenerateSignature(resultSnapshot, params.SignerPrivateKey)
	if err != nil {
		return err
	}

	model.Signatures = append(model.Signatures, &RawCardSignature{
		Signer:    params.Signer,
		Snapshot:  extraFieldsSnapshot,
		Signature: signature,
	})
	return nil
}

func (m *ModelSigner) CheckSignatureExists(model *RawSignedModel, params *SignParams) error {

	for _, s := range model.Signatures {
		if s.Signer == params.Signer {
			return errors.New(fmt.Sprintf("duplicate signer %s", s.Signer))
		}
	}
	return nil

}
