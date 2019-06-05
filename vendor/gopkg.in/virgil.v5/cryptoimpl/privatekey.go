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
	"bytes"
	"encoding/asn1"
	"encoding/pem"

	"github.com/agl/ed25519"
)

type ed25519PrivateKey struct {
	ID  []byte
	key []byte
}

func DecodePrivateKey(keyBytes, password []byte) (key *ed25519PrivateKey, err error) {
	unwrappedKey, keyType, err := unwrapKey(keyBytes)
	if err != nil {
		return nil, err
	}

	if keyType != "" && keyType != EC_PRIVATE_KEY && keyType != ENCRYPTED_PRIVATE_KEY {
		return nil, unsupported("key type")
	}

	if len(password) == 0 {
		key, err = loadPlainPrivateKey(unwrappedKey)
	} else {
		key, err = loadEncryptedPrivateKey(unwrappedKey, password)
	}
	return
}

func (k *ed25519PrivateKey) contents() []byte {
	return k.key
}

func (k *ed25519PrivateKey) Encode(password []byte) (res []byte, err error) {
	convertToPem := false
	if len(password) == 0 {
		res, err = encodePrivateKey(k, convertToPem)
	} else {
		res, err = encodePrivateKeyEncrypted(k, password, convertToPem)
	}
	return
}

func encodePrivateKey(privateKey *ed25519PrivateKey, encodeToPem bool) ([]byte, error) {
	if privateKey == nil || len(privateKey.key) != ed25519.PrivateKeySize {
		return nil, unsupported("key size")
	}

	rawKey := make([]byte, 34)
	copy(rawKey[2:], privateKey.key)
	rawKey[0] = 0x4
	rawKey[1] = 0x20

	key := privateKeyAsn{
		Version:    0,
		PrivateKey: rawKey,
		OID:        ed25519Algo,
	}

	serializedKey, err := asn1.Marshal(key)

	if err != nil {
		return nil, cryptoError(err, "")
	}

	if !encodeToPem {
		return serializedKey, nil
	} else {
		block := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: serializedKey,
		}
		return pem.EncodeToMemory(block), nil
	}
}
func encodePrivateKeyEncrypted(privateKey *ed25519PrivateKey, password []byte, encodeToPem bool) ([]byte, error) {

	serializedKey, err := encodePrivateKey(privateKey, false)

	if err != nil {
		return nil, err
	}

	kdfIv, iterations, keyIv, encryptedKey, err := encryptKeyWithPassword(serializedKey, password)
	if err != nil {
		return nil, err
	}

	alg, err := encodeKeyEncryptionAlgorithm(kdfIv, iterations, keyIv)
	if err != nil {
		return nil, err
	}

	asnKey := envelopeKey{
		CipherText: encryptedKey,
		Algorithm:  *alg,
	}
	envelopeBytes, err := asn1.Marshal(asnKey)

	if err != nil {
		return nil, cryptoError(err, "")
	}

	if !encodeToPem {
		return envelopeBytes, nil
	} else {
		block := &pem.Block{
			Type:  ENCRYPTED_PRIVATE_KEY,
			Bytes: envelopeBytes,
		}
		return pem.EncodeToMemory(block), nil
	}
}
func loadPlainPrivateKey(keyBytes []byte) (*ed25519PrivateKey, error) {

	key := &privateKeyAsn{}
	_, err := asn1.Unmarshal(keyBytes, key)
	if err != nil {
		return nil, cryptoError(err, "invalid data")
	}

	err = key.Validate()
	if err != nil {
		return nil, err
	}

	rawKey := key.PrivateKey[2:]
	buf := bytes.NewBuffer(rawKey)

	pub, priv, err := ed25519.GenerateKey(buf)
	if err != nil {
		return nil, cryptoError(err, "could not generate key")
	}

	edPub := &ed25519PublicKey{key: pub[:]}
	edpriv := &ed25519PrivateKey{key: priv[:]}

	snapshot, err := edPub.Encode()
	if err != nil {
		return nil, cryptoError(err, "")
	}

	edpriv.ID = calculateSHA512BasedIdentifier(snapshot)

	return edpriv, nil
}

func loadEncryptedPrivateKey(keyBytes, password []byte) (*ed25519PrivateKey, error) {
	parsedEncryptedKey := &envelopeKey{}
	_, err := asn1.Unmarshal(keyBytes, parsedEncryptedKey)
	if err != nil {
		return nil, cryptoError(err, "could not parse encrypted key")
	}

	keyIv, kdfIv, iterations, err := decodeKeyEncryptionAlgorithm(&parsedEncryptedKey.Algorithm)
	if err != nil {
		return nil, err
	}

	decryptedKey, err := decryptKeyWithPassword(parsedEncryptedKey.CipherText, keyIv, kdfIv, iterations, password)
	if err != nil {
		return nil, err
	}
	key, err := loadPlainPrivateKey(decryptedKey)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (k *ed25519PrivateKey) Empty() bool {
	return k == nil || len(k.key) == 0
}

func (k *ed25519PrivateKey) ExtractPublicKey() (*ed25519PublicKey, error) {
	if k.Empty() {
		return nil, CryptoError("private key is empty")
	}

	buf := bytes.NewBuffer(k.key)

	pub, _, err := ed25519.GenerateKey(buf)
	if err != nil {
		return nil, cryptoError(err, "could not generate key")
	}

	edPub := &ed25519PublicKey{key: pub[:]}

	edPub.ID = make([]byte, len(k.ID))
	copy(edPub.ID, k.ID)

	return edPub, nil
}

func (k *ed25519PrivateKey) IsPrivate() bool {
	return true
}

func (k *ed25519PrivateKey) Identifier() []byte {
	return k.ID
}
