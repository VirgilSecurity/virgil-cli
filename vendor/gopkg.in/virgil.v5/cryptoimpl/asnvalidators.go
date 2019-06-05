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

func unsupported(msg string) error {
	return CryptoError("Unsupported " + msg)
}

func (envelope *Envelope) Validate() error {
	if envelope.Version != 0 {
		return unsupported("envelope version")

	}

	if !envelope.Data.ContentType.Equal(oidEnvelopedData) {
		return unsupported("envelope type")
	}

	if len(envelope.CustomParams) > 0 {
		for _, e := range envelope.CustomParams {
			if e.Key == "chunkSize" {

			}
		}
	}

	return nil
}

func (content *envelopedData) Validate() error {

	if content.Version != 2 {
		return unsupported("content version")
	}

	info := content.EncryptedContentInfo

	if !info.ContentType.Equal(oidData) {
		return unsupported("encrypted data type")

	}

	if !info.ContentType.Equal(oidData) {
		return unsupported("encrypted data type")

	}

	if !info.ContentEncryptionAlgorithm.Algorithm.Equal(oidAesGCM) {
		return unsupported("encryption algorithm")
	}

	if len(info.ContentEncryptionAlgorithm.Parameters) != 12 {
		return unsupported("nonce size")
	}

	return nil
}
func (info *publicKeyRecipientInfo) Validate() error {
	if info.Version != 2 {
		return unsupported("public key recipient version")
	}

	if len(info.RecipientID) == 0 {
		return unsupported("empty recipient id for public key")
	}

	if !info.KeyEncryptionAlgorithm.Algorithm.Equal(oidEd25519key) {
		return unsupported("key encryption algorithm")
	}

	/*if len(info.EncryptedKey) != 242 {
		return unsupported("encrypted key data length")
	}*/

	return nil
}
func (key *encryptedKeyWithPublicKey) Validate() error {
	if key.Version != 0 {
		return unsupported("key version")
	}

	algo := key.PublicKey.Algorithm
	if !algo.Algorithm.Equal(oidEd25519key) {
		return unsupported("key encryption algorithm")
	}
	if key.PublicKey.PublicKey.BitLength != 256 {
		return unsupported("public key size")
	}

	kdf := key.KdfAlgo

	if !kdf.Oid.Equal(oidKdf2) || !kdf.HashAlgo.Algorithm.Equal(OidSha512) {
		return unsupported("kdf algorithm")
	}

	tag := key.Hmac

	if !tag.HmacAlgo.Algorithm.Equal(OidSha512) {
		return unsupported("hmac algorithm")
	}

	if len(tag.Value) != 64 {
		return unsupported("hmac size")
	}

	encryptedKey := key.EncryptedData

	if (!encryptedKey.CipherParams.Algorithm.Equal(oidAES256CBC) ||
		len(encryptedKey.CipherParams.Parameters) != 16) ||
		len(encryptedKey.Value) != 48 {
		return unsupported("key encryption algoritms or its parameters")
	}

	return nil
}
func (info *passwordRecipientInfo) Validate() error {
	if info.Version != 0 {
		return unsupported("password recipient version")
	}
	if len(info.EncryptedKey) != 48 {
		return unsupported("encrypted key size")
	}
	if !info.KeyEncryptionAlgorithm.Algorithm.Equal(oidPbeS2) {
		return unsupported("key encryption scheme")
	}

	if len(info.KeyEncryptionAlgorithm.Parameters.FullBytes) != 82 {
		return unsupported("key encryption parameters size")
	}

	return nil
}
func (p *pbeS2Parameters) Validate() error {

	scheme := p.EncryptionScheme
	kdf := p.KeyDerivationFunc

	if !scheme.Algorithm.Equal(oidAES256CBC) {
		return unsupported("key encryption algorithm")
	}

	if len(scheme.Parameters) != 16 {
		return unsupported("IV size")
	}

	if !kdf.Algorithm.Equal(oidPbkdf2) {
		return unsupported("kdf algorithm")
	}
	if len(kdf.Parameters.FullBytes) != 36 {
		return unsupported("kdf parameters size")
	}

	return nil
}
func (p *pkdf2Params) Validate() error {

	if p.IterationsCount < 3072 || p.IterationsCount > 8192 {
		return unsupported("iterations count")
	}
	if !p.Prf.Algorithm.Equal(oidHmacWithSha512) {
		return unsupported("prf algorithm")
	}
	if len(p.Salt) != 16 {
		return unsupported("prf kdf salt size")
	}

	return nil
}
func (k *publicKey) Validate() error {
	if !(k.Algorithm.Algorithm.Equal(oidEd25519key)) {
		return unsupported("public key type")
	}
	return nil
}

func (k *privateKeyAsn) Validate() error {
	if !(k.OID.Algorithm.Equal(oidEd25519key)) {
		return unsupported("key type")
	}

	if len(k.PrivateKey) != 34 || k.PrivateKey[0] != 0x04 || k.PrivateKey[1] != 0x20 { //2 bytes asn.1 octet string encoding + 32 bytes secret part
		return unsupported("private key size")
	}
	return nil
}
