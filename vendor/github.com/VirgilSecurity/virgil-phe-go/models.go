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
	"math/big"

	"github.com/pkg/errors"
)

func (m *EnrollmentRecord) validate() (t0, t1 *Point, err error) {

	if m == nil ||
		len(m.Nc) != pheNonceLen || len(m.Ns) != pheNonceLen {
		err = errors.New("invalid record")
		return
	}

	if t0, err = PointUnmarshal(m.T0); err != nil {
		return
	}

	t1, err = PointUnmarshal(m.T1)
	return
}

func (m *ProofOfSuccess) validate() (term1, term2, term3 *Point, blindX *big.Int, err error) {
	if m == nil {
		err = errors.New("invalid proof")
		return
	}

	if term1, err = PointUnmarshal(m.Term1); err != nil {
		return
	}

	if term2, err = PointUnmarshal(m.Term2); err != nil {
		return
	}

	if term3, err = PointUnmarshal(m.Term3); err != nil {
		return
	}

	if len(m.BlindX) != zLen {
		err = errors.New("invalid proof")
		return
	}
	blindX = new(big.Int).SetBytes(m.BlindX)

	return
}

func (m *ProofOfFail) validate() (term1, term2, term3, term4 *Point, blindA, blindB *big.Int, err error) {
	if m == nil {
		err = errors.New("invalid proof")
		return
	}

	if term1, err = PointUnmarshal(m.Term1); err != nil {
		return
	}

	if term2, err = PointUnmarshal(m.Term2); err != nil {
		return
	}

	if term3, err = PointUnmarshal(m.Term3); err != nil {
		return
	}

	if term4, err = PointUnmarshal(m.Term4); err != nil {
		return
	}

	if len(m.BlindA) != zLen {
		err = errors.New("invalid proof")
		return
	}

	if len(m.BlindB) != zLen {
		err = errors.New("invalid proof")
		return
	}

	blindA = new(big.Int).SetBytes(m.BlindA)
	blindB = new(big.Int).SetBytes(m.BlindB)

	return
}

func (m *UpdateToken) validate() (a, b *big.Int, err error) {
	if m == nil {
		return nil, nil, errors.New("invalid token")
	}
	if len(m.A) != zLen {
		return nil, nil, errors.New("invalid update token")
	}
	if len(m.B) != zLen {
		return nil, nil, errors.New("invalid update token")
	}

	a = new(big.Int).SetBytes(m.A)
	b = new(big.Int).SetBytes(m.B)
	return
}

//VerifyPasswordResult contains info about verification process result
type VerifyPasswordResult struct {
	Res  bool
	Salt []byte
}
