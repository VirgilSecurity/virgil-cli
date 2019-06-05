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

import (
	"math/big"
)

// GF represents galois field over prime
type GF struct {
	P *big.Int
}

var (
	one   = big.NewInt(1)
	two   = big.NewInt(2)
	three = big.NewInt(3)
	four  = big.NewInt(4)
)

//Neg negates number over GFp
func (g *GF) Neg(a *big.Int) *big.Int {
	return new(big.Int).Sub(g.P, a)
}

//NegBytes negates number over GFp represented by a byte array
func (g *GF) NegBytes(a []byte) *big.Int {
	return new(big.Int).Sub(g.P, new(big.Int).SetBytes(a))
}

//Square does a^2 over GFp
func (g *GF) Square(a *big.Int) *big.Int {
	return new(big.Int).Exp(a, two, g.P)
}

//Cube does a^3 over GFp
func (g *GF) Cube(a *big.Int) *big.Int {
	return new(big.Int).Exp(a, three, g.P)
}

//Pow does a^b over GFp
func (g *GF) Pow(a, b *big.Int) *big.Int {
	return new(big.Int).Exp(a, b, g.P)
}

//Inv does modulo inverse over GFp
func (g *GF) Inv(a *big.Int) *big.Int {
	return new(big.Int).ModInverse(a, g.P)
}

//InvBytes does modulo inverse over GFp represented by a byte array
func (g *GF) InvBytes(a []byte) *big.Int {
	return new(big.Int).ModInverse(new(big.Int).SetBytes(a), g.P)
}

//Add adds two numbers over GFp
func (g *GF) Add(a, b *big.Int) *big.Int {
	add := new(big.Int).Add(a, b)
	return add.Mod(add, g.P)
}

//AddBytes adds two numbers one of which is represented as byte array over GFp
func (g *GF) AddBytes(a []byte, b *big.Int) *big.Int {
	add := new(big.Int).Add(new(big.Int).SetBytes(a), b)
	return add.Mod(add, g.P)
}

//Sub subtracts two numbers over GFp
func (g *GF) Sub(a, b *big.Int) *big.Int {

	negB := new(big.Int).Sub(a, b)
	return negB.Mod(negB, g.P)
}

//Mul multiplies two numbers over GFp
func (g *GF) Mul(a, b *big.Int) *big.Int {
	mul := new(big.Int).Mul(a, b)
	return mul.Mod(mul, g.P)
}

//MulBytes multiplies two numbers one of which is represented as a byte array over GFp
func (g *GF) MulBytes(a []byte, b *big.Int) *big.Int {
	mul := new(big.Int).Mul(new(big.Int).SetBytes(a), b)
	return mul.Mod(mul, g.P)
}

// Div multiplies a number by an inverse of another number over GFp
func (g *GF) Div(a, b *big.Int) *big.Int {
	invB := g.Inv(b)
	t := g.Mul(a, invB)
	return t
}
