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
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"fmt"

	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

const Curve25519PrivateKeySize = 32
const Curve25519PublicKeySize = 32
const Curve25519SharedKeySize = 32

func decryptSymmetricKeyWithECIES(encryptedSymmetricKey, tag, ephPub, iv, privateKey []byte) ([]byte, error) {

	if len(ephPub) != ed25519.PublicKeySize {
		return nil, CryptoError("invalid ed25519 public key size")
	}

	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, CryptoError("invalid ed25519 private key size")
	}

	sharedSecret := new([Curve25519SharedKeySize]byte)
	mySecret := new([ed25519.PrivateKeySize]byte)
	hisPublic := new([ed25519.PublicKeySize]byte)
	myCurveSecret := new([Curve25519PrivateKeySize]byte)
	hisCurvePublic := new([Curve25519PublicKeySize]byte)
	copy(mySecret[:], privateKey)
	copy(hisPublic[:], ephPub)

	extra25519.PrivateKeyToCurve25519(myCurveSecret, mySecret)
	extra25519.PublicKeyToCurve25519(hisCurvePublic, hisPublic)
	defer ZeroData(mySecret[:])
	defer ZeroData(myCurveSecret[:])

	//compute shared secret
	curve25519.ScalarMult(sharedSecret, myCurveSecret, hisCurvePublic)
	err := checkSharedSecret(sharedSecret[:])
	if err != nil {
		err = cryptoError(err, "")
		return nil, err
	}
	defer ZeroData(sharedSecret[:])
	//derive keys
	keys := kdf2(sharedSecret[:], 96, Hash.New) // 32 bytes - AES key + 64 bytes HMAC key
	defer ZeroData(keys)

	//calculate mac
	mac := hmac.New(Hash.New, keys[32:])
	mac.Write(encryptedSymmetricKey)
	macResult := mac.Sum(nil)

	if subtle.ConstantTimeCompare(macResult, tag) == 1 {
		//compare with tag
		//decrypt symmetric key
		ciph, err := aes.NewCipher(keys[:32])
		if err != nil {
			return nil, cryptoError(err, "")
		}
		aesCBC := cipher.NewCBCDecrypter(ciph, iv)
		deciphered := make([]byte, len(encryptedSymmetricKey))
		aesCBC.CryptBlocks(deciphered, encryptedSymmetricKey)
		ciphertextKey, err := pkcs7Unpad(deciphered, aesCBC.BlockSize())
		if err != nil {
			return nil, cryptoError(err, "")
		}
		return ciphertextKey, nil
	}
	return nil, CryptoError("Tag does not match")
}

func encryptSymmetricKeyWithECIES(publicKey, symmetricKey []byte) (encryptedSymmetricKey, tag, ephPub, iv []byte, err error) {

	if len(publicKey) != ed25519.PublicKeySize {
		err = CryptoError(fmt.Sprintf("invalid ed25519 key size %d", len(publicKey)))
		return
	}

	keypair, err := NewKeypair()
	if err != nil {
		err = cryptoError(err, "")
		return
	}
	ephPub = keypair.PublicKey().contents()
	ephPrivate := new([ed25519.PrivateKeySize]byte)
	ephCurvePrivate := new([Curve25519PrivateKeySize]byte)
	sharedSecret := new([Curve25519SharedKeySize]byte)
	hisPublic := new([ed25519.PublicKeySize]byte)
	hisCurvePublic := new([Curve25519PublicKeySize]byte)

	iv = make([]byte, aes.BlockSize)
	_, err = rand.Reader.Read(iv)
	if err != nil {
		err = cryptoError(err, "")
		return
	}
	copy(hisPublic[:], publicKey)
	copy(ephPrivate[:], keypair.PrivateKey().contents())

	extra25519.PrivateKeyToCurve25519(ephCurvePrivate, ephPrivate)
	extra25519.PublicKeyToCurve25519(hisCurvePublic, hisPublic)

	defer ZeroData(ephPrivate[:])
	defer ZeroData(ephCurvePrivate[:])

	//calculate DH between his public and ephemeral private keys. Ephemeral public key will be bundled inside the message
	curve25519.ScalarMult(sharedSecret, ephCurvePrivate, hisCurvePublic)
	err = checkSharedSecret(sharedSecret[:])
	if err != nil {
		err = cryptoError(err, "")
		return
	}
	defer ZeroData(sharedSecret[:])
	//derive keys
	keys := kdf2(sharedSecret[:], 96, Hash.New) // 32 bytes - AES key + 64 bytes HMAC key
	defer ZeroData(keys)

	//encrypt symmetric key
	ciph, err := aes.NewCipher(keys[:32])
	if err != nil {
		err = cryptoError(err, "")
		return
	}
	aesCBC := cipher.NewCBCEncrypter(ciph, iv)
	paddedKey, err := pkcs7Pad(symmetricKey, ciph.BlockSize())
	if err != nil {
		err = cryptoError(err, "")
		return
	}
	encryptedSymmetricKey = make([]byte, len(paddedKey))
	aesCBC.CryptBlocks(encryptedSymmetricKey, paddedKey)

	//calculate tag
	mac := hmac.New(Hash.New, keys[32:])
	mac.Write(encryptedSymmetricKey)
	tag = mac.Sum(nil)

	return encryptedSymmetricKey, tag, ephPub, iv, nil
}

func checkSharedSecret(sk []byte) error {
	var b byte = 0
	for _, skb := range sk {
		b |= skb
	}
	if b == 0 {
		return CryptoError("invalid DH result")
	}
	return nil
}
