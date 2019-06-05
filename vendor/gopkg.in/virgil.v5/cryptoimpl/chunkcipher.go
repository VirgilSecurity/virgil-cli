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
	"io"

	"gopkg.in/virgil.v5/cryptoimpl/gcm"
)

type VirgilChunkCipher interface {
	Encrypt(key, nonce, ad []byte, chunkSize int, in io.Reader, out io.Writer) error
	Decrypt(key, nonce, ad []byte, chunkSize int, in io.Reader, out io.Writer) error
}

var DefaultChunkSize = 1024 * 1024

type aesGCMChunkStreamCipher struct{}

const (
	gcmTagSize = 16
)

func (c *aesGCMChunkStreamCipher) Encrypt(key, nonce, ad []byte, chunkSize int, in io.Reader, out io.Writer) error {

	if chunkSize < 1 {
		return CryptoError("chunk size too small")
	}

	buf := make([]byte, chunkSize+gcmTagSize)

	var counter = make([]byte, len(nonce))
	var chunkNonce = make([]byte, len(nonce))

	n, err := in.Read(buf[:chunkSize])
	for n > 0 && err == nil {
		gcm.XorBytes(chunkNonce, nonce, counter)
		ciph, _ := aes.NewCipher(key)
		aesGCM, _ := cipher.NewGCM(ciph)

		res := aesGCM.Seal(buf[:0], chunkNonce, buf[:n], ad)

		written, err := out.Write(res)
		if written != len(res) || err != nil {
			return CryptoError("Could not write to output virgilbuffer")
		}

		increment(counter)
		n, err = in.Read(buf[:chunkSize])
	}

	if err != nil && err != io.EOF {
		return err
	}
	return nil
}
func (c *aesGCMChunkStreamCipher) Decrypt(key, nonce, ad []byte, chunkSize int, in io.Reader, out io.Writer) error {
	if chunkSize < 1 {
		return CryptoError("chunk size too small")
	}

	buf := make([]byte, chunkSize+gcmTagSize)

	var counter = make([]byte, len(nonce))
	var chunkNonce = make([]byte, len(nonce))

	n, err := in.Read(buf)
	for n > 0 && err == nil {
		gcm.XorBytes(chunkNonce, nonce, counter)
		ciph, _ := aes.NewCipher(key)
		aesGCM, _ := cipher.NewGCM(ciph)

		res, err := aesGCM.Open(buf[:0], chunkNonce, buf[:n], ad)
		if err != nil {
			return err
		}
		written, err := out.Write(res)
		if written != len(res) || err != nil {
			return CryptoError("Could not write to output virgilbuffer")
		}
		increment(counter)
		n, err = in.Read(buf)
	}

	if err != nil && err != io.EOF {
		return err
	}
	return nil
}

func increment(counter []byte) {
	for i := len(counter) - 1; i >= 0; i-- {
		counter[i]++
		if counter[i] != 0 {
			break
		}
	}
}
