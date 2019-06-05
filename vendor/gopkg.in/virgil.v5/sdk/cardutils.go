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
	"encoding/hex"

	"time"

	"gopkg.in/virgil.v5/cryptoapi"
	"gopkg.in/virgil.v5/errors"
)

func ParseRawCard(crypto cryptoapi.CardCrypto, model *RawSignedModel, isOutdated bool) (*Card, error) {

	if crypto == nil {
		return nil, errors.New("crypto is mandatory")
	}
	if model == nil {
		return nil, errors.New("model is mandatory")
	}

	var content *RawCardContent
	err := ParseSnapshot(model.ContentSnapshot, &content)
	if err != nil {
		return nil, err
	}

	var signatures []*CardSignature
	for _, signature := range model.Signatures {

		var extraFields map[string]string
		if len(signature.Snapshot) > 0 {
			err := ParseSnapshot(signature.Snapshot, &extraFields)
			if err != nil {
				extraFields = nil
			}
		}
		signatures = append(signatures, &CardSignature{
			Snapshot:    signature.Snapshot,
			Signer:      signature.Signer,
			Signature:   signature.Signature,
			ExtraFields: extraFields,
		})
	}

	id, err := GenerateCardId(crypto, model.ContentSnapshot)
	if err != nil {
		return nil, err
	}

	publicKey, err := crypto.ImportPublicKey(content.PublicKey)
	if err != nil {
		return nil, err
	}

	return &Card{
		Id:              id,
		ContentSnapshot: model.ContentSnapshot,
		Signatures:      signatures,
		Version:         content.Version,
		PreviousCardId:  content.PreviousCardId,
		CreatedAt:       time.Unix(content.CreatedAt, 0),
		Identity:        content.Identity,
		IsOutdated:      isOutdated,
		PublicKey:       publicKey,
	}, nil
}

func GenerateCardId(crypto cryptoapi.CardCrypto, data []byte) (string, error) {
	if crypto == nil {
		return "", errors.New("crypto is mandatory")
	}

	return hex.EncodeToString(crypto.GenerateSHA512(data)[:32]), nil
}

func ParseRawCards(crypto cryptoapi.CardCrypto, models ...*RawSignedModel) ([]*Card, error) {

	if crypto == nil {
		return nil, errors.New("crypto is mandatory")
	}
	if models == nil {
		return nil, errors.New("model is mandatory")
	}

	var cards []*Card

	for _, model := range models {

		card, err := ParseRawCard(crypto, model, false)
		if err != nil {
			return nil, err
		}
		cards = append(cards, card)

	}
	return cards, nil
}

func LinkCards(cards ...*Card) []*Card {
	unsortedCards := make(map[string]*Card)
	var result []*Card
	for _, card := range cards {
		unsortedCards[card.Id] = card
	}

	for _, card := range cards {
		if card.PreviousCardId != "" {
			prev, ok := unsortedCards[card.PreviousCardId]
			if ok {
				card.PreviousCard = prev
				prev.IsOutdated = true
				delete(unsortedCards, card.PreviousCardId)
			}
		}
	}

	for _, card := range unsortedCards {
		result = append(result, card)
	}
	return result
}
