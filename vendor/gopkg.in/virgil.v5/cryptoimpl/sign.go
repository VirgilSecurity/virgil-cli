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
	"io"
	"strconv"

	"crypto/sha512"

	"github.com/agl/ed25519"
	"github.com/minio/sha256-simd"
	"gopkg.in/virgil.v5/errors"
)

type VirgilSigner interface {
	Sign(data []byte, signer *ed25519PrivateKey) ([]byte, error)
	SignHash(hash []byte, signer *ed25519PrivateKey) ([]byte, error)
	SignStream(data io.Reader, signer *ed25519PrivateKey) ([]byte, error)
}

type VirgilVerifier interface {
	Verify(data []byte, key *ed25519PublicKey, signature []byte) error
	VerifyHash(hash []byte, key *ed25519PublicKey, signature []byte) error
	VerifyStream(data io.Reader, key *ed25519PublicKey, signature []byte) error
}

var Signer VirgilSigner
var Verifier VirgilVerifier

type ed25519Signer struct{}
type ed25519Verifier struct{}

func (s *ed25519Signer) Sign(data []byte, signer *ed25519PrivateKey) ([]byte, error) {
	if signer == nil || signer.Empty() {
		return nil, errors.New("key is nil")
	}
	hash := Hash.Sum(data)
	return signInternal(hash, signer)

}

func (s *ed25519Signer) SignHash(hash []byte, signer *ed25519PrivateKey) ([]byte, error) {
	if signer == nil || signer.Empty() {
		return nil, errors.New("key is nil")
	}
	return signInternal(hash, signer)

}

func (s *ed25519Verifier) Verify(data []byte, key *ed25519PublicKey, signature []byte) error {
	if key == nil || key.Empty() {
		return errors.New("key is nil")
	}

	return verifyInternal(data, key, signature, false)
}

func (s *ed25519Verifier) VerifyHash(hash []byte, key *ed25519PublicKey, signature []byte) error {
	if key == nil || key.Empty() {
		return errors.New("key is nil")
	}

	return verifyInternal(hash, key, signature, true)
}

func (s *ed25519Signer) SignStream(data io.Reader, signer *ed25519PrivateKey) ([]byte, error) {
	if signer == nil || signer.Empty() {
		return nil, errors.New("key is nil")
	}
	h, err := hashStream(data)
	if err != nil {
		return nil, err
	}
	return signInternal(h, signer)
}
func (s *ed25519Verifier) VerifyStream(data io.Reader, key *ed25519PublicKey, signature []byte) error {
	if key == nil || key.Empty() {
		return errors.New("key is nil")
	}
	h, err := hashStream(data)
	if err != nil {
		return err
	}
	return verifyInternal(h, key, signature, true)
}

func signInternal(hash []byte, key *ed25519PrivateKey) ([]byte, error) {
	if key == nil || key.Empty() {
		return nil, CryptoError("No private key for signing")
	}
	private := new([ed25519.PrivateKeySize]byte)
	copy(private[:], key.contents())

	sign := ed25519.Sign(private, hash[:])

	sBytes, err := makeSignature(sign[:], len(hash))

	if err != nil {
		return nil, err
	}

	return sBytes, nil
}
func verifyInternal(data []byte, key *ed25519PublicKey, signature []byte, doNotHash bool) error {
	if key == nil || key.Empty() {
		return CryptoError("public key for verification is not provided")
	}
	if len(key.contents()) != ed25519.PublicKeySize {
		return CryptoError("Invalid key size for signature")
	}

	sign, algo, err := decodeSignature(signature)
	if err != nil {
		return err
	}

	var hash []byte

	if doNotHash {
		hash = data
	} else {
		if algo.Equal(OidSha256) {
			tmp := sha256.Sum256(data)
			hash = tmp[:]
		} else if algo.Equal(OidSha384) {
			tmp := sha512.Sum384(data)
			hash = tmp[:]
		} else if algo.Equal(OidSha512) {
			tmp := sha512.Sum512(data)
			hash = tmp[:]
		} else {
			return cryptoError(errors.New("unsupported signature hash"), algo.String())
		}
	}

	if err != nil {
		return err
	}

	if len(sign) != ed25519.SignatureSize {
		return CryptoError("Invalid signature size " + strconv.Itoa(len(sign)))
	}

	signatureBytes := new([ed25519.SignatureSize]byte)
	pub := new([ed25519.PublicKeySize]byte)
	copy(signatureBytes[:], sign)
	copy(pub[:], key.contents())

	res := ed25519.Verify(pub, hash, signatureBytes)
	if !res {
		return CryptoError("signature validation failed")
	}
	return nil
}

func hashStream(data io.Reader) ([]byte, error) {
	hash := Hash.New()
	buf := make([]byte, 1024*1024)
	read, err := data.Read(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}

	for ; read > 0 && (err == nil || err == io.EOF); read, err = data.Read(buf) {
		hash.Write(buf[:read])
	}

	if err != nil && err != io.EOF {
		return nil, err
	}
	return hash.Sum(nil), nil
}

func init() {
	Signer = &ed25519Signer{}
	Verifier = &ed25519Verifier{}
}
