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

package cryptoimpl

import (
	"encoding/asn1"
	"encoding/pem"

	"golang.org/x/crypto/ed25519"
)

type ed25519PublicKey struct {
	ID  []byte
	key []byte
}

func DecodePublicKey(keyBytes []byte) (*ed25519PublicKey, error) {
	unwrappedKey, keyType, err := unwrapKey(keyBytes)
	if err != nil {
		return nil, err
	}

	if keyType != "" && keyType != PUBLIC_KEY {
		return nil, unsupported("key type")
	}

	publicKey := &publicKey{}
	_, err = asn1.Unmarshal(unwrappedKey, publicKey)
	if err != nil {
		return nil, CryptoError("invalid data")
	}
	err = publicKey.Validate()
	if err != nil {
		return nil, err
	}

	key := publicKey.Key.Bytes

	edPublicKey := &ed25519PublicKey{key: key}
	snapshot, err := edPublicKey.Encode()
	if err != nil {
		return nil, err
	}

	edPublicKey.ID = calculateSHA512BasedIdentifier(snapshot)
	return edPublicKey, nil
}

func (k *ed25519PublicKey) contents() []byte {
	return k.key
}

func (k *ed25519PublicKey) Identifier() []byte {
	return k.ID
}

func (k *ed25519PublicKey) Encode() ([]byte, error) {
	encodeToPem := false
	if len(k.key) != ed25519.PublicKeySize {
		return nil, unsupported("key size")
	}

	key := publicKey{}
	key.Algorithm = algorithmIdentifierWithOidParameter{Algorithm: oidEd25519key}
	key.Key = asn1.BitString{Bytes: k.key}
	rawKey, err := asn1.Marshal(key)
	if err != nil {
		return nil, cryptoError(err, "")
	}
	if !encodeToPem {
		return rawKey, nil
	} else {
		block := &pem.Block{
			Type:  PUBLIC_KEY,
			Bytes: rawKey,
		}
		return pem.EncodeToMemory(block), nil
	}
}

func (k *ed25519PublicKey) Empty() bool {
	return k == nil || len(k.key) == 0
}

func (k *ed25519PublicKey) IsPublic() bool {
	return true
}
