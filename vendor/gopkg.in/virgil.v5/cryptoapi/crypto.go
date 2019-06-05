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

package cryptoapi

type CardCrypto interface {
	GenerateSignature(data []byte, key interface {
		IsPrivate() bool
		Identifier() []byte
	}) ([]byte, error)
	VerifySignature(data []byte, signature []byte, key interface {
		IsPublic() bool
		Identifier() []byte
	}) error
	ExportPublicKey(key interface {
		IsPublic() bool
		Identifier() []byte
	}) ([]byte, error)
	ImportPublicKey(publicKeySrc []byte) (interface {
		IsPublic() bool
		Identifier() []byte
	}, error)
	GenerateSHA512(data []byte) []byte
}

type AccessTokenSigner interface {
	GenerateTokenSignature(data []byte, privateKey interface {
		IsPrivate() bool
		Identifier() []byte
	}) ([]byte, error)
	VerifyTokenSignature(data []byte, signature []byte, publicKey interface {
		IsPublic() bool
		Identifier() []byte
	}) error
	GetAlgorithm() string
}

type PrivateKeyExporter interface {
	ExportPrivateKey(key interface {
		IsPrivate() bool
		Identifier() []byte
	}) ([]byte, error)
	ImportPrivateKey(data []byte) (interface {
		IsPrivate() bool
		Identifier() []byte
	}, error)
}

type PrivateKey interface {
	IsPrivate() bool
	Identifier() []byte
}
type PublicKey interface {
	IsPublic() bool
	Identifier() []byte
}

type Keypair interface {
	PublicKey() interface {
		IsPublic() bool
		Identifier() []byte
	}

	PrivateKey() interface {
		IsPrivate() bool
		Identifier() []byte
	}
}
