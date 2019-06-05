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

package swu

/*
 Implementation of Simple Shallue-Woestijne-Ulas algorithm in Go
*/

import (
	"crypto/elliptic"
	"crypto/sha512"
	"math/big"
)

var (
	p        = elliptic.P256().Params().P
	a        *big.Int // a = -3
	b        = elliptic.P256().Params().B
	mba      *big.Int
	gf       = &GF{p}
	p34, p14 *big.Int
	//PointHashLen is the length of a number that represents the point
	PointHashLen = 32
)

func init() {
	a = gf.Neg(three)
	ba := gf.Div(b, a)
	mba = gf.Neg(ba)
	p34 = new(big.Int).Div(a, four) // a ==(p-3)
	p1 := new(big.Int).Add(p, one)
	p14 = new(big.Int).Div(p1, four)
}

//DataToPoint hashes data using SHA-256 and maps it to a point on curve
func DataToPoint(data []byte) (x, y *big.Int) {
	hash := sha512.Sum512(data)
	return HashToPoint(hash[:PointHashLen])
}

//HashToPoint maps 32 byte hash to a point on curve
func HashToPoint(hash []byte) (x, y *big.Int) {

	if len(hash) != PointHashLen {
		panic("invalid hash length")
	}

	t := new(big.Int).SetBytes(hash)

	//alpha = -t^2
	tt := gf.Square(t)
	alpha := gf.Neg(tt)
	asq := gf.Square(alpha)
	asqa := gf.Add(asq, alpha)
	asqa1 := gf.Add(one, gf.Inv(asqa))

	// x2 = -(b / a) * (1 + 1/(alpha^2+alpha))
	x2 := gf.Mul(mba, asqa1)

	//x3 = alpha * x2
	x3 := gf.Mul(alpha, x2)
	ax2 := gf.Mul(a, x2)
	x23 := gf.Cube(x2)
	x23ax2 := gf.Add(x23, ax2)

	// h2 = x2^3 + a*x2 + b
	h2 := gf.Add(x23ax2, b)

	ax3 := gf.Mul(a, x3)
	x33 := gf.Cube(x3)
	x33ax3 := gf.Add(x33, ax3)

	// h3 = x3^3 + a*x3 + b
	h3 := gf.Add(x33ax3, b)

	// tmp = h2 ^ ((p - 3) // 4)
	tmp := gf.Pow(h2, p34)
	tmp2 := gf.Square(tmp)
	tmp2h2 := gf.Mul(tmp2, h2)

	//if tmp^2 * h2 == 1:
	if tmp2h2.Cmp(one) == 0 {
		// return (x2, tmp * h2 )
		return x2, gf.Mul(tmp, h2)
	}

	//return (x3, h3 ^ ((p+1)//4))
	return x3, gf.Pow(h3, p14)
}
