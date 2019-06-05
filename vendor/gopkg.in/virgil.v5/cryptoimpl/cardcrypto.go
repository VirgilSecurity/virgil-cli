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

import "crypto/sha512"

type VirgilCardCrypto struct {
	Crypto *VirgilCrypto
}

func NewVirgilCardCrypto() *VirgilCardCrypto {
	return &VirgilCardCrypto{
		Crypto: NewVirgilCrypto(),
	}
}

func (c *VirgilCardCrypto) GenerateSignature(data []byte, key interface {
	IsPrivate() bool
	Identifier() []byte
}) ([]byte, error) {
	return c.Crypto.Sign(data, key)
}

func (c *VirgilCardCrypto) VerifySignature(data []byte, signature []byte, key interface {
	IsPublic() bool
	Identifier() []byte
}) error {
	return c.Crypto.VerifySignature(data, signature, key)
}

func (c *VirgilCardCrypto) ExportPublicKey(key interface {
	IsPublic() bool
	Identifier() []byte
}) ([]byte, error) {
	return c.Crypto.ExportPublicKey(key)
}

func (c *VirgilCardCrypto) ImportPublicKey(data []byte) (interface {
	IsPublic() bool
	Identifier() []byte
}, error) {
	return c.Crypto.ImportPublicKey(data)
}

func (c *VirgilCardCrypto) GenerateSHA512(data []byte) []byte {
	hash := sha512.Sum512(data)
	return hash[:]
}
