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
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"

	"github.com/agl/ed25519"
)

// KeyType denotes algorithm used for key generation. See keytypes package
type KeyType int

var NewKeypair func() (*ed25519Keypair, error)

const EC_PRIVATE_KEY = "PRIVATE KEY"
const ENCRYPTED_PRIVATE_KEY = "ENCRYPTED PRIVATE KEY"
const PUBLIC_KEY = "PUBLIC KEY"

const MINIMAL_KEY_LENGTH = 32

type ed25519Keypair struct {
	publicKey  *ed25519PublicKey
	privateKey *ed25519PrivateKey
}

func generateEd25519Keypair() (*ed25519Keypair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)

	if err != nil {
		return nil, cryptoError(err, "")
	}

	pub := &ed25519PublicKey{key: publicKey[:]}
	priv := &ed25519PrivateKey{key: privateKey[:]}
	kp := &ed25519Keypair{}
	kp.publicKey = pub
	kp.privateKey = priv

	snapshot, err := pub.Encode()
	if err != nil {
		return nil, cryptoError(err, "")
	}
	fp := calculateSHA512BasedIdentifier(snapshot)

	pub.ID = fp
	priv.ID = make([]byte, len(fp))
	copy(priv.ID, fp)

	return kp, nil
}
func (e *ed25519Keypair) HasPublic() bool {
	return e.publicKey != nil && !e.publicKey.Empty()
}
func (e *ed25519Keypair) HasPrivate() bool {
	return e.privateKey != nil && !e.privateKey.Empty()
}
func (e *ed25519Keypair) PublicKey() *ed25519PublicKey {
	return e.publicKey
}
func (e *ed25519Keypair) PrivateKey() *ed25519PrivateKey {
	return e.privateKey
}

func unwrapKey(key []byte) ([]byte, string, error) {

	if len(key) < MINIMAL_KEY_LENGTH {
		return nil, "", CryptoError("key length is too small")
	}

	block, _ := pem.Decode(key)
	if block != nil {
		return block.Bytes, block.Type, nil
	} else {
		buf := make([]byte, base64.StdEncoding.DecodedLen(len(key)))

		read, err := base64.StdEncoding.Decode(buf, key)

		if err == nil {
			return buf[:read], "", nil
		}

		return key, "", nil //already DER
	}
}

func init() {
	NewKeypair = generateEd25519Keypair
}
