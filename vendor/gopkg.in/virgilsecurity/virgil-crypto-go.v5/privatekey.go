/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2015-2018, Virgil Security, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package virgil_crypto_go

type externalPrivateKey struct {
	receiverID []byte
	key        []byte
}

func (k *externalPrivateKey) contents() []byte {
	return k.key
}

func (k *externalPrivateKey) Identifier() []byte {
	return k.receiverID
}

func (k *externalPrivateKey) Encode(password []byte) ([]byte, error) {
	if len(password) == 0 {

		vkey := ToVirgilByteArray(k.key)
		defer DeleteVirgilByteArray(vkey)
		venc := VirgilKeyPairPrivateKeyToDER(vkey)
		defer DeleteVirgilByteArray(venc)

		return ToSlice(venc), nil
	} else {
		vkey := ToVirgilByteArray(k.key)
		defer DeleteVirgilByteArray(vkey)
		vpass := ToVirgilByteArray([]byte(password))
		defer DeleteVirgilByteArray(vpass)
		return ToSlice(VirgilKeyPairEncryptPrivateKey(vkey, vpass)), nil
	}
}

func (k *externalPrivateKey) Empty() bool {
	return k == nil || len(k.key) == 0
}

func (k *externalPrivateKey) ExtractPublicKey() (*externalPublicKey, error) {
	vkey := ToVirgilByteArray(k.key)
	defer DeleteVirgilByteArray(vkey)
	vempty := ToVirgilByteArray(make([]byte, 0))
	defer DeleteVirgilByteArray(vempty)
	pub := VirgilKeyPairExtractPublicKey(vkey, vempty)
	defer DeleteVirgilByteArray(pub)
	vder := VirgilKeyPairPublicKeyToDER(pub)
	defer DeleteVirgilByteArray(vder)

	derPub := ToSlice(vder)
	return &externalPublicKey{
		key:        derPub,
		receiverID: k.receiverID,
	}, nil
}

func (k *externalPrivateKey) IsPrivate() bool {
	return true
}
