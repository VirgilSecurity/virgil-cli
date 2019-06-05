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
	"gopkg.in/virgil.v5/cryptoapi"
	"gopkg.in/virgil.v5/errors"
)

type CardVerifier interface {
	VerifyCard(card *Card) error
}

type CardVerifierError struct {
	errors.SDKError
}

func NewCardVerifierError(msg string) error {
	return CardVerifierError{SDKError: errors.SDKError{
		Message: msg,
	}}
}

func ToCardVerifierError(err error) (CardVerifierError, bool) {
	e, ok := errors.Cause(err).(CardVerifierError)
	return e, ok
}

const (
	VirgilPublicKey = "MCowBQYDK2VwAyEAljOYGANYiVq1WbvVvoYIKtvZi2ji9bAhxyu6iV/LF8M="
)

type VirgilCardVerifier struct {
	Crypto                cryptoapi.CardCrypto
	VerifySelfSignature   bool
	VerifyVirgilSignature bool
	Whitelists            []*Whitelist
	virgilPublicKey       cryptoapi.PublicKey
}

func NewVirgilCardVerifier(crypto cryptoapi.CardCrypto, verifySelfSignature, verifyVirgilSignature bool, whitelists ...*Whitelist) (*VirgilCardVerifier, error) {

	verifier := &VirgilCardVerifier{
		Crypto:                crypto,
		Whitelists:            whitelists,
		VerifySelfSignature:   verifySelfSignature,
		VerifyVirgilSignature: verifyVirgilSignature,
	}

	if err := verifier.SelfCheck(); err != nil {
		return nil, err
	}

	if verifyVirgilSignature {
		if pub, err := verifier.GetPublicKeyFromBase64(VirgilPublicKey); err != nil {
			return nil, err
		} else {
			verifier.virgilPublicKey = pub
		}

	}
	return verifier, nil
}

func (v *VirgilCardVerifier) SelfCheck() error {
	if v.Crypto == nil {
		return NewCardVerifierError("Crypto is not set")
	}
	return nil
}

func (v *VirgilCardVerifier) SetWhitelists(whitelists []*Whitelist) {
	v.Whitelists = whitelists
}

func (v *VirgilCardVerifier) VerifyCard(card *Card) error {
	if card.PublicKey == nil {
		return NewCardVerifierError("card public key is not set")
	}

	if v.VerifySelfSignature {
		if err := v.ValidateSignerSignature(card, SelfSigner, card.PublicKey); err != nil {
			return errors.Wrap(CardValidationSignatureValidationFailedErr, err.Error())
		}
	}

	if v.VerifyVirgilSignature {
		if v.virgilPublicKey == nil {
			return NewCardVerifierError("Virgil public key is not set")
		}
		if err := v.ValidateSignerSignature(card, VirgilSigner, v.virgilPublicKey); err != nil {
			return errors.Wrap(CardValidationSignatureValidationFailedErr, err.Error())
		}
	}

	if len(v.Whitelists) == 0 {
		return nil
	}

	hasNil := false
	hasNonNil := false

	for _, whitelist := range v.Whitelists {

		if whitelist == nil {
			hasNil = true
			continue
		} else {
			hasNonNil = true
		}

		ok := false
		var lastErr error
		for _, cred := range whitelist.VerifierCredentials {
			err := v.ValidateSignerSignature(card, cred.Signer, cred.PublicKey)
			if err == nil {
				ok = true
				break
			} else {
				lastErr = errors.Wrap(CardValidationSignatureValidationFailedErr, err.Error())
			}
		}

		if !ok {
			if lastErr == nil {
				lastErr = CardValidationExpectedSignerWasNotFoundErr
			}

			return lastErr
		}
	}

	if hasNil && hasNonNil {
		return errors.New("can't mix nil and non nil whitelists")
	}

	return nil
}

func (v *VirgilCardVerifier) GetPublicKeyFromBase64(str string) (cryptoapi.PublicKey, error) {
	return v.Crypto.ImportPublicKey([]byte(str))
}

func (v *VirgilCardVerifier) ValidateSignerSignature(card *Card, signer string, publicKey cryptoapi.PublicKey) error {
	if err := v.SelfCheck(); err != nil {
		return err
	}
	if len(card.Signatures) == 0 {
		return CardValidationExpectedSignerWasNotFoundErr
	}
	for _, s := range card.Signatures {

		if s.Signer == signer {
			snapshot := append(card.ContentSnapshot, s.Snapshot...)
			err := v.Crypto.VerifySignature(snapshot, s.Signature, publicKey)
			if err != nil {
				return err
			} else {
				return nil
			}
		}
	}
	return CardValidationExpectedSignerWasNotFoundErr
}

func (v *VirgilCardVerifier) ReplaceVirgilPublicKey(newKey string) error {
	if pub, err := v.GetPublicKeyFromBase64(newKey); err != nil {
		return err
	} else {
		v.virgilPublicKey = pub
		return nil
	}
}
