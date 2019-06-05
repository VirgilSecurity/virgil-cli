/*
 * Copyright (C) 2015-2019 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
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
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

package phe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"

	"github.com/VirgilSecurity/virgil-phe-go/swu"
	"github.com/golang/protobuf/proto"

	"github.com/pkg/errors"
)

var (
	randReader = rand.Reader
	curve      = elliptic.P256()
	curveG     = new(Point).ScalarBaseMultInt(new(big.Int).SetUint64(1)).Marshal()
	gf         = swu.GF{P: curve.Params().N}

	//domains
	commonPrefix     = []byte{0x56, 0x52, 0x47, 0x4c, 0x50, 0x48, 0x45} //VRGLPHE
	dhc0             = append(commonPrefix, 0x31)
	dhc1             = append(commonPrefix, 0x32)
	dhs0             = append(commonPrefix, 0x33)
	dhs1             = append(commonPrefix, 0x34)
	proofOk          = append(commonPrefix, 0x35)
	proofError       = append(commonPrefix, 0x36)
	encrypt          = append(commonPrefix, 0x37)
	kdfInfoZ         = append(commonPrefix, 0x38)
	kdfInfoClientKey = append(commonPrefix, 0x39)
)

const (
	pheNonceLen     = 32
	pheClientKeyLen = 32
	symKeyLen       = 32
	symSaltLen      = 32
	symNonceLen     = 12
	symTagLen       = 16
	zLen            = 32
)

// Read is a helper function that calls Reader.Read using io.ReadFull.
// On return, n == len(b) if and only if err == nil.
func randRead(b []byte) {
	_, err := io.ReadFull(randReader, b)
	if err != nil {
		panic(err)
	}
}

//hash hashes a slice of byte arrays,
func hash(domain []byte, tuple ...[]byte) []byte {
	hash := sha512.New()
	/* #nosec */
	hash.Write(domain)
	for _, t := range tuple {
		/* #nosec */
		hash.Write(t)
	}
	return hash.Sum(nil)
}

// initKdf creates HKDF instance initialized with hash
func initKdf(domain []byte, tuple ...[]byte) io.Reader {
	key := hash(nil, tuple...)

	return hkdf.New(sha512.New, key, domain, kdfInfoZ)

}

// randomZ generates big random 256 bit integer which must be less than curve's N parameter
func randomZ() (z *big.Int) {
	rz := makeZ(randReader)
	for z == nil {
		// If the scalar is out of range, sample another random number.
		if rz.Cmp(curve.Params().N) >= 0 {
			rz = makeZ(randReader)
		} else {
			z = rz
		}
	}
	return
}

// hashZ maps arrays of bytes to an integer less than curve's N parameter
func hashZ(domain []byte, data ...[]byte) (z *big.Int) {
	xof := initKdf(domain, data...)
	rz := makeZ(xof)

	for z == nil {
		// If the scalar is out of range, extract another number.
		if rz.Cmp(curve.Params().N) >= 0 {
			rz = makeZ(xof)
		} else {
			z = rz
		}
	}
	return
}

func makeZ(reader io.Reader) *big.Int {
	buf := make([]byte, zLen)
	n, err := reader.Read(buf)
	if err != nil || n != zLen {
		panic("random read failed")
	}
	return new(big.Int).SetBytes(buf)
}

//padZ makes all bytes equal size adding zeroes to the beginning if necessary
func padZ(z []byte) []byte {
	if len(z) == zLen {
		return z
	}

	newZ := make([]byte, zLen)
	copy(newZ[zLen-len(z):], z)
	return newZ
}

// hashToPoint maps arrays of bytes to a valid curve point
func hashToPoint(domain []byte, data ...[]byte) *Point {
	hash := hash(domain, data...)
	x, y := swu.HashToPoint(hash[:swu.PointHashLen])
	return &Point{x, y}
}

func marshalKeypair(publicKey, privateKey []byte) ([]byte, error) {
	kp := &Keypair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}

	return proto.Marshal(kp)
}

func unmarshalKeypair(serverKeypair []byte) (kp *Keypair, err error) {

	kp = &Keypair{}
	err = proto.Unmarshal(serverKeypair, kp)
	if err != nil {
		return nil, errors.Wrap(err, "invalid keypair")
	}

	return
}

// Encrypt generates 32 byte salt, uses master key & salt to generate per-data key & nonce with the help of HKDF
// Salt is concatenated to the ciphertext
func Encrypt(data, key []byte) ([]byte, error) {

	if len(key) != symKeyLen {
		return nil, errors.New("key must be exactly 32 bytes")
	}

	salt := make([]byte, symSaltLen)
	randRead(salt)

	kdf := hkdf.New(sha512.New, key, salt, encrypt)

	keyNonce := make([]byte, symKeyLen+symNonceLen)
	_, err := kdf.Read(keyNonce)
	if err != nil {
		return nil, err
	}

	aesgcm, err := aes.NewCipher(keyNonce[:symKeyLen])
	if err != nil {
		return nil, err
	}

	aesGcm, err := cipher.NewGCM(aesgcm)
	if err != nil {
		return nil, err
	}

	ct := make([]byte, symSaltLen+len(data)+aesGcm.Overhead())
	copy(ct, salt)

	aesGcm.Seal(ct[:symSaltLen], keyNonce[symKeyLen:], data, nil)
	return ct, nil
}

// Decrypt extracts 32 byte salt, derives key & nonce and decrypts ciphertext
func Decrypt(ciphertext, key []byte) ([]byte, error) {
	if len(key) != symKeyLen {
		return nil, errors.New("key must be exactly 32 bytes")
	}

	if len(ciphertext) < (symSaltLen + symTagLen) {
		return nil, errors.New("invalid ciphertext length")
	}

	salt := ciphertext[:symSaltLen]
	kdf := hkdf.New(sha512.New, key, salt, encrypt)

	keyNonce := make([]byte, symKeyLen+symNonceLen)
	_, err := kdf.Read(keyNonce)
	if err != nil {
		return nil, err
	}

	aesgcm, err := aes.NewCipher(keyNonce[:symKeyLen])
	if err != nil {
		return nil, err
	}

	aesGcm, err := cipher.NewGCM(aesgcm)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, 0)
	return aesGcm.Open(dst, keyNonce[symKeyLen:], ciphertext[symSaltLen:], nil)

}
