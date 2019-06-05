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
	"io"

	"gopkg.in/virgil.v5/cryptoimpl/gcm"
)

type VirgilStreamCipher interface {
	Encrypt(key, nonce, ad []byte, in io.Reader, out io.Writer) error
	Decrypt(key, nonce, ad []byte, in io.Reader, out io.Writer) error
}

var StreamCipher VirgilStreamCipher
var ChunkCipher VirgilChunkCipher

type aesGCMStreamCipher struct{}

func (c *aesGCMStreamCipher) Encrypt(key, nonce, ad []byte, in io.Reader, out io.Writer) error {
	ciph, _ := aes.NewCipher(key)
	aesGCM, _ := gcm.NewGCM(ciph)
	return aesGCM.SealStream(nonce, ad, in, out)
}
func (c *aesGCMStreamCipher) Decrypt(key, nonce, ad []byte, in io.Reader, out io.Writer) error {
	ciph, _ := aes.NewCipher(key)
	aesGCM, _ := gcm.NewGCM(ciph)
	return aesGCM.OpenStream(nonce, ad, in, out)
}

func init() {
	StreamCipher = &aesGCMStreamCipher{}
	ChunkCipher = &aesGCMChunkStreamCipher{}
}
