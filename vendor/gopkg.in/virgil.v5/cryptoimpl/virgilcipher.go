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
	"crypto/subtle"
	"encoding/asn1"
	"io"
)

type Cipher interface {
	AddKeyRecipient(key *ed25519PublicKey) error
	AddPasswordRecipient(password []byte)
	Encrypt(data []byte) ([]byte, error)
	DecryptWithPassword(data []byte, password []byte) ([]byte, error)
	DecryptWithPrivateKey(data []byte, key *ed25519PrivateKey) ([]byte, error)
	EncryptStream(in io.Reader, out io.Writer) error
	DecryptStream(in io.Reader, out io.Writer, key *ed25519PrivateKey) error
	SignThenEncrypt(data []byte, signerKey *ed25519PrivateKey) ([]byte, error)
	DecryptThenVerify(data []byte, decryptionKey *ed25519PrivateKey, verifierPublicKeys ...*ed25519PublicKey) ([]byte, error)
}

type defaultCipher struct {
	recipients   []recipient
	streamCipher VirgilStreamCipher
	chunkCipher  VirgilChunkCipher
}

var newCipherFunc func() Cipher

const (
	signatureKey = "VIRGIL-DATA-SIGNATURE"
	signerId     = "VIRGIL-DATA-SIGNER-ID"
)

func NewCipher() Cipher {
	return newCipherFunc()
}

//recipient is a type that's responsible for encrypting\decrypting a random symmetric key
type recipient interface {
	encryptKey(symmetricKey []byte) (*asn1.RawValue, error)
	decryptKey(id []byte, key []byte) ([]byte, error)
}

func (c *defaultCipher) AddKeyRecipient(key *ed25519PublicKey) error {

	if key == nil || key.Empty() {
		return CryptoError("no public key provided")
	}

	recipient := &publicKeyRecipient{
		ID:        key.Identifier(),
		PublicKey: key.contents(),
	}

	c.recipients = append(c.recipients, recipient)
	return nil
}

func (c *defaultCipher) AddPasswordRecipient(password []byte) {
	recipient := &passwordRecipient{Password: password}

	c.recipients = append(c.recipients, recipient)
}
func (c *defaultCipher) Encrypt(data []byte) ([]byte, error) {
	if len(c.recipients) == 0 {
		return nil, CryptoError("No recipients specified")
	}

	var models []*asn1.RawValue

	ciphertext, symmetricKey, nonce := encryptData(data)

	for _, r := range c.recipients {
		model, err := r.encryptKey(symmetricKey)
		if err != nil {
			return nil, err
		}
		models = append(models, model)
	}

	envelope, err := composeCMSMessage(nonce, models, nil)

	if err != nil {
		return nil, err
	}
	return append(envelope, ciphertext...), nil
}

func (c *defaultCipher) SignThenEncrypt(data []byte, signer *ed25519PrivateKey) ([]byte, error) {
	if len(c.recipients) == 0 {
		return nil, CryptoError("No recipients specified")
	}

	signature, err := Signer.Sign(data, signer)
	if err != nil {
		return nil, err
	}

	customParams := map[string]interface{}{
		signatureKey: signature,
		signerId:     signer.Identifier(),
	}
	var models []*asn1.RawValue

	ciphertext, symmetricKey, nonce := encryptData(data)

	for _, r := range c.recipients {
		model, err := r.encryptKey(symmetricKey)
		if err != nil {
			return nil, err
		}
		models = append(models, model)
	}

	envelope, err := composeCMSMessage(nonce, models, customParams)

	if err != nil {
		return nil, err
	}
	return append(envelope, ciphertext...), nil
}

func (c *defaultCipher) DecryptWithPassword(data []byte, password []byte) ([]byte, error) {
	_, ciphertext, nonce, recipients, err := decodeCMSMessage(data)
	if err != nil {
		return nil, err
	}
	for _, r := range recipients {
		key, err := r.decryptKey(nil, password)
		if err == nil {
			return decryptData(ciphertext, key, nonce)
		}
	}
	return nil, CryptoError("Could not decrypt the symmetric key. Wrong password?")
}
func (c *defaultCipher) DecryptWithPrivateKey(data []byte, key *ed25519PrivateKey) ([]byte, error) {

	if key == nil || len(key.contents()) == 0 {
		return nil, CryptoError("no keypair provided")
	}

	_, ciphertext, nonce, recipients, err := decodeCMSMessage(data)
	if err != nil {
		return nil, err
	}
	for _, r := range recipients {
		key, err := r.decryptKey(key.Identifier(), key.contents())
		if err == nil {
			return decryptData(ciphertext, key, nonce)
		}

	}
	return nil, CryptoError("Could not decrypt the symmetric key. Wrong private key?")
}

func (c *defaultCipher) DecryptThenVerify(data []byte, decryptionKey *ed25519PrivateKey, verifierPublicKeys ...*ed25519PublicKey) ([]byte, error) {

	if decryptionKey == nil || decryptionKey.Empty() {
		return nil, CryptoError("no keypair provided")
	}

	if len(verifierPublicKeys) == 0 {
		return nil, CryptoError("no verifiers provided")
	}

	customParams, ciphertext, nonce, recipients, err := decodeCMSMessage(data)
	if err != nil {
		return nil, err
	}

	var signature, signerIdValue []byte
	if len(customParams) > 0 {

		if signatureValue, ok := customParams[signatureKey]; ok {
			if tmp, ok := signatureValue.(*[]byte); ok {
				signature = *tmp
			} else {
				return nil, CryptoError("got signature but could not decode")
			}
		}

		if signerId, ok := customParams[signerId]; ok {
			if tmp, ok := signerId.(*[]byte); ok {
				signerIdValue = *tmp
			} else {
				return nil, CryptoError("got signerId but could not decode")
			}
		}
	}
	for _, r := range recipients {
		key, err := r.decryptKey(decryptionKey.Identifier(), decryptionKey.contents())
		if err == nil {
			data, err := decryptData(ciphertext, key, nonce)
			if err != nil {
				return nil, err
			}

			for _, v := range verifierPublicKeys {
				if len(signerIdValue) > 0 {
					//found match
					if subtle.ConstantTimeCompare(signerIdValue, v.Identifier()) == 1 {
						err := Verifier.Verify(data, v, signature)
						if err != nil {
							return nil, CryptoError("signature validation failed")
						}
						if err != nil {
							return nil, err
						}
						return data, nil
					}
				} else {
					err := Verifier.Verify(data, v, signature)
					if err == nil {
						return data, nil
					}
				}
			}

			return nil, CryptoError("Could not verify signature with provided public keys")

		}

	}
	return nil, CryptoError("Could not decrypt the symmetric key. Wrong private key?")
}

func (c *defaultCipher) EncryptStream(in io.Reader, out io.Writer) error {
	if len(c.recipients) == 0 {
		return CryptoError("No recipients specified")
	}

	var models []*asn1.RawValue

	symmetricKey := make([]byte, 32) //256 bit AES key
	nonce := make([]byte, 12)        //96 bit AES GCM nonce

	rand.Reader.Read(symmetricKey)
	rand.Reader.Read(nonce)

	for _, r := range c.recipients {
		model, err := r.encryptKey(symmetricKey)
		if err != nil {
			return err
		}
		models = append(models, model)
	}

	envelope, err := composeCMSMessage(nonce, models, map[string]interface{}{"chunkSize": DefaultChunkSize})

	if err != nil {
		return err
	}
	written, err := out.Write(envelope)
	if err != nil || written < len(envelope) {
		return cryptoError(err, "could not write to the output stream")
	}

	return c.chunkCipher.Encrypt(symmetricKey, nonce, nil, DefaultChunkSize, in, out)
}
func (c *defaultCipher) DecryptStream(in io.Reader, out io.Writer, key *ed25519PrivateKey) error {

	if key == nil || len(key.contents()) == 0 {
		return CryptoError("no keypair provided")
	}

	//read header
	buf := make([]byte, 16)
	read, err := in.Read(buf)
	if read != len(buf) {
		return cryptoError(err, "Could not read from stream")
	}
	ret, offset, err := parseTagAndLength(buf, 0)
	if err != nil {
		return cryptoError(err, "Error while parsing stream header")
	}
	if offset < len(buf) {
		ret.length -= len(buf) - offset
	}

	header := make([]byte, ret.length)
	read, err = in.Read(header)
	if read != len(header) {
		return cryptoError(err, "Could not read from stream")
	}
	header = append(buf, header...)
	customParams, rest, nonce, recipients, err := decodeCMSMessage(header)
	chunkSize := 0
	if len(customParams) > 0 {
		if chunkValue, ok := customParams["chunkSize"]; ok {
			if tmp, ok := chunkValue.(*int); ok {
				chunkSize = *tmp
			} else {
				return CryptoError("got chunkSize but could not decode")
			}

		}
	}

	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return CryptoError("Some data is left after header parsing")
	}
	for _, r := range recipients {
		key, err := r.decryptKey(key.Identifier(), key.contents())
		if err == nil {

			if chunkSize > 0 {
				return c.chunkCipher.Decrypt(key, nonce, nil, chunkSize, in, out)
			}

			return c.streamCipher.Decrypt(key, nonce, nil, in, out)
		}

	}
	return CryptoError("Could not decrypt the symmetric key. Wrong private key?")
}

func encryptData(data []byte) (cipherText, symmetricKey, nonce []byte) {
	symmetricKey = make([]byte, 32) //256 bit AES key
	nonce = make([]byte, 12)        //96 bit AES GCM nonce

	rand.Reader.Read(symmetricKey)
	rand.Reader.Read(nonce)

	ciph, _ := aes.NewCipher(symmetricKey)
	aesGCM, _ := cipher.NewGCM(ciph)
	cipherText = aesGCM.Seal(nil, nonce, data, nil)
	return
}
func decryptData(ciphertext, key, nonce []byte) ([]byte, error) {
	ciph, err := aes.NewCipher(key)

	if err != nil {
		return nil, cryptoError(err, "")
	}

	aesgcm, err := cipher.NewGCM(ciph)

	if err != nil {
		return nil, cryptoError(err, "")
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, cryptoError(err, "")
	}
	return plaintext, nil
}

func init() {
	newCipherFunc = func() Cipher {
		return &defaultCipher{
			streamCipher: StreamCipher,
			chunkCipher:  ChunkCipher,
		}
	}
}
