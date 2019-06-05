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
	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
	"github.com/minio/sha256-simd"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func EDHInit(ICa, EKa *ed25519PrivateKey, ICb, LTCb, OTCb *ed25519PublicKey) ([]byte, error) {

	dh1, err := dhED25519(ICa, LTCb)
	if err != nil {
		return nil, err
	}

	dh2, err := dhED25519(EKa, ICb)
	if err != nil {
		return nil, err
	}

	dh3, err := dhED25519(EKa, LTCb)
	if err != nil {
		return nil, err
	}

	sk := append(dh1, dh2...)
	sk = append(sk, dh3...)

	if OTCb != nil {

		dh4, err := dhED25519(EKa, OTCb)
		if err != nil {
			return nil, err
		}

		sk = append(sk, dh4...)
	}

	kdf := hkdf.New(sha256.New, sk, nil, nil)

	res := make([]byte, 128)
	kdf.Read(res)
	return res, nil

}

func EDHRespond(ICa, EKa *ed25519PublicKey, ICb, LTCb, OTCb *ed25519PrivateKey) ([]byte, error) {

	dh1, err := dhED25519(LTCb, ICa)
	if err != nil {
		return nil, err
	}

	dh2, err := dhED25519(ICb, EKa)
	if err != nil {
		return nil, err
	}

	dh3, err := dhED25519(LTCb, EKa)
	if err != nil {
		return nil, err
	}

	sk := append(dh1, dh2...)
	sk = append(sk, dh3...)

	if OTCb != nil {

		dh4, err := dhED25519(OTCb, EKa)
		if err != nil {
			return nil, err
		}

		sk = append(sk, dh4...)
	}

	kdf := hkdf.New(sha256.New, sk, nil, nil)

	res := make([]byte, 128)
	kdf.Read(res)
	return res, nil

}

func dhED25519(priv *ed25519PrivateKey, pub *ed25519PublicKey) ([]byte, error) {

	edPub := new([ed25519.PublicKeySize]byte)
	edPriv := new([ed25519.PrivateKeySize]byte)

	curvePriv := new([Curve25519PrivateKeySize]byte)
	curvePub := new([Curve25519PublicKeySize]byte)

	copy(edPub[:], pub.contents())
	copy(edPriv[:], priv.contents())

	extra25519.PublicKeyToCurve25519(curvePub, edPub)
	extra25519.PrivateKeyToCurve25519(curvePriv, edPriv)

	sk := new([Curve25519SharedKeySize]byte)
	curve25519.ScalarMult(sk, curvePriv, curvePub)

	return sk[:], checkSharedSecret(sk[:])
}
