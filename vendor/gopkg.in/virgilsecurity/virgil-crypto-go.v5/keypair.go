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

import (
	"encoding/base64"
	"encoding/pem"
)

type externalKeypair struct {
	publicKey  *externalPublicKey
	privateKey *externalPrivateKey
}

func (e *externalKeypair) HasPublic() bool {
	return e.publicKey != nil && !e.publicKey.Empty()
}
func (e *externalKeypair) HasPrivate() bool {
	return e.privateKey != nil && !e.privateKey.Empty()
}
func (e *externalKeypair) PublicKey() interface {
	IsPublic() bool
	Identifier() []byte
} {
	return e.publicKey
}
func (e *externalKeypair) PrivateKey() interface {
	IsPrivate() bool
	Identifier() []byte
} {
	return e.privateKey
}

func unwrapKey(key []byte) []byte {

	block, _ := pem.Decode(key)
	if block != nil {
		return block.Bytes
	} else {
		buf := make([]byte, base64.StdEncoding.DecodedLen(len(key)))

		read, err := base64.StdEncoding.Decode(buf, key)

		if err == nil {
			return buf[:read]
		}

		return key //already DER
	}
}
