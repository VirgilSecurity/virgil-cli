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
	"crypto/rand"
	"encoding/asn1"
	"math/big"

	"golang.org/x/crypto/pbkdf2"
)

type passwordRecipient struct {
	Password            []byte
	kdfIv               []byte
	iterations          int
	encryptedKey, keyIv []byte
}

func (p *passwordRecipient) encryptKey(symmetricKey []byte) (*asn1.RawValue, error) {
	kdfIv, iterations, keyIv, encryptedKey, err := encryptKeyWithPassword(symmetricKey, []byte(p.Password))
	if err != nil {
		return nil, CryptoError(err.Error())
	}
	return makePasswordRecipient(kdfIv, iterations, encryptedKey, keyIv)
}
func (p *passwordRecipient) decryptKey(id []byte, password []byte) ([]byte, error) {
	if len(id) > 0 {
		return nil, CryptoError("Wrong recipient")
	}
	return decryptKeyWithPassword(p.encryptedKey, p.keyIv, p.kdfIv, p.iterations, password)
}
func encryptKeyWithPassword(randomKey, password []byte) (kdfIv []byte, iterations int, keyIv, encryptedKey []byte, err error) {

	kdfIv = make([]byte, 16)
	keyIv = make([]byte, 16)

	_, err = rand.Read(kdfIv)
	if err != nil {
		return
	}
	_, err = rand.Read(keyIv)
	if err != nil {
		return
	}

	randomIterationsPart, _ := rand.Int(rand.Reader, big.NewInt(5121))
	iterations = 3072 + int(randomIterationsPart.Int64())

	//generate key for random key encryption based on password
	keyEncryptionKey := pbkdf2.Key(password, kdfIv, iterations, 32, Hash.New)

	ciph, _ := aes.NewCipher(keyEncryptionKey)
	aesCBC := cipher.NewCBCEncrypter(ciph, keyIv)
	paddedKey, _ := pkcs7Pad(randomKey, aesCBC.BlockSize())
	encryptedKey = make([]byte, len(paddedKey))
	aesCBC.CryptBlocks(encryptedKey, paddedKey)

	return
}
func decryptKeyWithPassword(encryptedKey, keyIv, kdfIv []byte, iterations int, password []byte) ([]byte, error) {

	keyEncryptionKey := pbkdf2.Key(password, kdfIv, iterations, 32, Hash.New)

	ciph, _ := aes.NewCipher(keyEncryptionKey)
	aesCBC := cipher.NewCBCDecrypter(ciph, keyIv)
	paddedKey := make([]byte, len(encryptedKey))
	aesCBC.CryptBlocks(paddedKey, encryptedKey)

	unpaddedKey, err := pkcs7Unpad(paddedKey, aesCBC.BlockSize())
	if err != nil {
		return nil, &WrongPasswordError{"could not decrypt key with password"}
	}
	return unpaddedKey, nil
}
