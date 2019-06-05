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
	"crypto/elliptic"
	"math/big"

	"github.com/pkg/errors"
)

// Point represents an elliptic curve point
type Point struct {
	X, Y *big.Int
}

var (
	pn   = curve.Params().P
	zero = big.NewInt(0)
)

// PointUnmarshal validates & converts byte array to an elliptic curve point object
func PointUnmarshal(data []byte) (*Point, error) {
	if len(data) != 65 {
		return nil, errors.New("Invalid curve point")
	}
	x, y := elliptic.Unmarshal(curve, data)
	if x == nil || y == nil {
		return nil, errors.New("Invalid curve point")
	}
	return &Point{
		X: x,
		Y: y,
	}, nil
}

// Add adds two points
func (p *Point) Add(a *Point) *Point {
	x, y := curve.Add(p.X, p.Y, a.X, a.Y)
	return &Point{x, y}
}

// Neg inverts point's Y coordinate
func (p *Point) Neg() *Point {
	t := new(Point)
	t.X = p.X
	t.Y = new(big.Int).Sub(pn, p.Y)
	return t
}

// ScalarMult multiplies point to a number
func (p *Point) ScalarMult(b []byte) *Point {
	x, y := curve.ScalarMult(p.X, p.Y, b)

	return &Point{x, y}
}

// ScalarMultInt multiplies point to a number
func (p *Point) ScalarMultInt(b *big.Int) *Point {
	x, y := curve.ScalarMult(p.X, p.Y, b.Bytes())

	return &Point{x, y}
}

// ScalarBaseMult multiplies base point to a number
func (p *Point) ScalarBaseMult(b []byte) *Point {
	x, y := curve.ScalarBaseMult(b)

	return &Point{x, y}
}

// ScalarBaseMultInt multiplies base point to a number
func (p *Point) ScalarBaseMultInt(b *big.Int) *Point {
	x, y := curve.ScalarBaseMult(b.Bytes())

	return &Point{x, y}
}

// Marshal converts point to an array of bytes
func (p *Point) Marshal() []byte {

	if p.X.Cmp(zero) != 0 &&
		p.Y.Cmp(zero) != 0 {
		return elliptic.Marshal(curve, p.X, p.Y)
	}
	panic("zero point")
}

// Equal checks two points for equality
func (p *Point) Equal(other *Point) bool {
	return p.X.Cmp(other.X) == 0 &&
		p.Y.Cmp(other.Y) == 0
}
