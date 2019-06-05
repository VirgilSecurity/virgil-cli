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

package gcm

import (
	"crypto/cipher"
	"crypto/subtle"
	"io"

	"github.com/pkg/errors"
)

var (
	GCMBlockSizeIncorrectErr   = errors.New("cipher: NewGCM requires 128-bit block cipher")
	GCMNonceLengthIncorrectErr = errors.New("cipher: incorrect nonce length given to GCM")
)

const GcmStreamBufSize = 1024 * 1024 //megabyte virgilbuffer

type gcmFieldElement struct {
	low, high uint64
}

// gcm represents a Galois Counter Mode with a specific key. See
// http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
type gcm struct {
	cipher    cipher.Block
	nonceSize int
	// productTable contains the first sixteen powers of the key, H.
	// However, they are in bit reversed order. See NewGCMWithNonceSize.
	productTable [16]gcmFieldElement
}

// NewGCM returns the given 128-bit, block cipher wrapped in Galois Counter Mode
// with the standard nonce length.
func NewGCM(cipher cipher.Block) (*gcm, error) {
	return newGCMWithNonceSize(cipher, gcmStandardNonceSize)
}

// NewGCMWithNonceSize returns the given 128-bit, block cipher wrapped in Galois
// Counter Mode, which accepts nonces of the given length.
//
// Only use this function if you require compatibility with an existing
// cryptosystem that uses non-standard nonce lengths. All other users should use
// NewGCM, which is faster and more resistant to misuse.
func newGCMWithNonceSize(cipher cipher.Block, size int) (*gcm, error) {

	if cipher.BlockSize() != gcmBlockSize {
		return nil, GCMBlockSizeIncorrectErr
	}

	var key [gcmBlockSize]byte
	cipher.Encrypt(key[:], key[:])

	g := &gcm{cipher: cipher, nonceSize: size}

	// We precompute 16 multiples of |key|. However, when we do lookups
	// into this table we'll be using bits from a field element and
	// therefore the bits will be in the reverse order. So normally one
	// would expect, say, 4*key to be in index 4 of the table but due to
	// this bit ordering it will actually be in index 0010 (base 2) = 2.
	x := gcmFieldElement{
		getUint64(key[:8]),
		getUint64(key[8:]),
	}
	g.productTable[reverseBits(1)] = x

	for i := 2; i < 16; i += 2 {
		g.productTable[reverseBits(i)] = gcmDouble(&g.productTable[reverseBits(i/2)])
		g.productTable[reverseBits(i+1)] = gcmAdd(&g.productTable[reverseBits(i)], &x)
	}

	return g, nil
}

const (
	gcmBlockSize         = 16
	gcmTagSize           = 16
	gcmStandardNonceSize = 12
)

func (g *gcm) NonceSize() int {
	return g.nonceSize
}

func (*gcm) Overhead() int {
	return gcmTagSize
}

func (g *gcm) SealStream(nonce, data []byte, plain io.Reader, ciph io.Writer) error {

	if len(nonce) != g.nonceSize {
		return GCMNonceLengthIncorrectErr
	}

	var counter, tagMask [gcmBlockSize]byte
	g.deriveCounter(&counter, nonce)
	g.cipher.Encrypt(tagMask[:], counter[:])
	gcmInc32(&counter)

	inBuf := make([]byte, GcmStreamBufSize)
	var plainLen uint64

	//GCM init

	var y gcmFieldElement
	g.update(&y, data)
	n, err := plain.Read(inBuf)
	for n > 0 && err == nil {
		buf := inBuf[:n]
		g.counterCrypt(buf, buf, &counter)
		g.update(&y, buf)
		written, err := ciph.Write(buf)
		if written != len(buf) || err != nil {
			return errors.Wrap(err, "cipher: could not write to output virgilbuffer")
		}
		plainLen += uint64(n)
		n, err = plain.Read(inBuf)
	}
	if err != nil && err != io.EOF {
		return errors.Wrap(err, "cipher: could not read from input virgilbuffer")
	}

	y.low ^= uint64(len(data)) * 8
	y.high ^= plainLen * 8

	g.mul(&y)
	tag := make([]byte, gcmBlockSize)
	putUint64(tag, y.low)
	putUint64(tag[8:], y.high)
	xorWords(tag, tag, tagMask[:])

	ciph.Write(tag)

	return nil
}

func (g *gcm) OpenStream(nonce, data []byte, ciphertext io.Reader, plaintext io.Writer) error {
	if len(nonce) != g.nonceSize {
		return GCMNonceLengthIncorrectErr
	}
	//GCM init
	var counter, tagMask [gcmBlockSize]byte
	g.deriveCounter(&counter, nonce)
	g.cipher.Encrypt(tagMask[:], counter[:])
	gcmInc32(&counter)

	inBuf := make([]byte, GcmStreamBufSize)

	var cipherLen uint64
	var y gcmFieldElement
	g.update(&y, data)

	var expectedTag, lastTagPart, previousTagPart []byte

	n, err := ciphertext.Read(inBuf)
	for n > 0 && err == nil {
		lastTagPart, expectedTag, err = processTag(inBuf, previousTagPart, n)

		if err != nil {
			return errors.New("Data is corrupt, discard the stream")
		}

		//we need to deal with the last chunk part. Either keep it for the future, use it as tag or treat it as data
		buf := make([]byte, n)
		copy(buf, inBuf[:n])
		if lastTagPart == nil { // we're sure that we have the tag
			if n <= gcmTagSize {
				if len(previousTagPart) == 0 {
					buf = nil
				} else {
					buf = previousTagPart[:n]
				}

			} else {
				buf = append(previousTagPart, buf[:n-gcmTagSize]...)
			}
		} else if n < gcmTagSize { //a part of tag belongs to previous data chunk stored in tagPart
			expectedTag = append(previousTagPart[gcmTagSize-n:], lastTagPart...)
			buf = previousTagPart[:n]
		} else {
			buf = append(previousTagPart, buf[:n-gcmTagSize]...)
			if len(previousTagPart) == 0 {
				previousTagPart = make([]byte, len(lastTagPart))
			}
			copy(previousTagPart, lastTagPart) //avoid virgilbuffer corruption when reading next chunk
		}
		g.update(&y, buf)
		g.counterCrypt(buf, buf, &counter)

		written, err := plaintext.Write(buf)

		if written != len(buf) || err != nil {
			return errors.Wrap(err, "Could not write to output virgilbuffer")
		}
		cipherLen += uint64(len(buf))
		n, err = ciphertext.Read(inBuf)
	}
	if err != nil && err != io.EOF {
		return errors.Wrap(err, "cipher: could not read from input virgilbuffer")
	}

	y.low ^= uint64(len(data)) * 8
	y.high ^= cipherLen * 8

	g.mul(&y)
	tag := make([]byte, gcmBlockSize)
	putUint64(tag, y.low)
	putUint64(tag[8:], y.high)

	xorWords(tag, tag, tagMask[:])

	tagResult := subtle.ConstantTimeCompare(tag, expectedTag)
	if tagResult != 1 {
		return errors.New("Tags don't match, discard the stream")
	}
	return nil

}
func processTag(buf []byte, tagPart []byte, readBytes int) (lastTagPart, expectedTag []byte, err error) {
	if readBytes == len(buf) { // we can't be sure the last part of the chunk is the tag, so save it for the future use
		lastTagPart = buf[len(buf)-gcmTagSize:]
		expectedTag = lastTagPart
		return lastTagPart, expectedTag, nil
	}

	if readBytes < len(buf) { //last chunk is not full, means it definitely contains tag or it's part
		if readBytes >= gcmTagSize { // this chunk is the last chunk, contains tag
			expectedTag = buf[readBytes-gcmTagSize : readBytes]
			return nil, expectedTag, err
		}
		if readBytes < gcmTagSize && len(tagPart) == gcmTagSize { //tag was split between previous chunk & last chunk
			expectedTag = append(tagPart[readBytes:], buf[:readBytes]...)
			return nil, expectedTag, nil
		}

		return nil, nil, errors.New("Data is too small to contain tag")
	}

	return nil, nil, errors.New("Data error") //should never happen
}

// reverseBits reverses the order of the bits of 4-bit number in i.
func reverseBits(i int) int {
	i = ((i << 2) & 0xc) | ((i >> 2) & 0x3)
	i = ((i << 1) & 0xa) | ((i >> 1) & 0x5)
	return i
}

// gcmAdd adds two elements of GF(2¹²⁸) and returns the sum.
func gcmAdd(x, y *gcmFieldElement) gcmFieldElement {
	// Addition in a characteristic 2 field is just XOR.
	return gcmFieldElement{x.low ^ y.low, x.high ^ y.high}
}

// gcmDouble returns the result of doubling an element of GF(2¹²⁸).
func gcmDouble(x *gcmFieldElement) (double gcmFieldElement) {
	msbSet := x.high&1 == 1

	// Because of the bit-ordering, doubling is actually a right shift.
	double.high = x.high >> 1
	double.high |= x.low << 63
	double.low = x.low >> 1

	// If the most-significant bit was set before shifting then it,
	// conceptually, becomes a term of x^128. This is greater than the
	// irreducible polynomial so the result has to be reduced. The
	// irreducible polynomial is 1+x+x^2+x^7+x^128. We can subtract that to
	// eliminate the term at x^128 which also means subtracting the other
	// four terms. In characteristic 2 fields, subtraction == addition ==
	// XOR.
	if msbSet {
		double.low ^= 0xe100000000000000
	}

	return
}

var gcmReductionTable = []uint16{
	0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
	0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
}

// mul sets y to y*H, where H is the GCM key, fixed during NewGCMWithNonceSize.
func (g *gcm) mul(y *gcmFieldElement) {
	var z gcmFieldElement

	for i := 0; i < 2; i++ {
		word := y.high
		if i == 1 {
			word = y.low
		}

		// Multiplication works by multiplying z by 16 and adding in
		// one of the precomputed multiples of H.
		for j := 0; j < 64; j += 4 {
			msw := z.high & 0xf
			z.high >>= 4
			z.high |= z.low << 60
			z.low >>= 4
			z.low ^= uint64(gcmReductionTable[msw]) << 48

			// the values in |table| are ordered for
			// little-endian bit positions. See the comment
			// in NewGCMWithNonceSize.
			t := &g.productTable[word&0xf]

			z.low ^= t.low
			z.high ^= t.high
			word >>= 4
		}
	}

	*y = z
}

// updateBlocks extends y with more polynomial terms from blocks, based on
// Horner's rule. There must be a multiple of gcmBlockSize bytes in blocks.
func (g *gcm) updateBlocks(y *gcmFieldElement, blocks []byte) {
	for len(blocks) > 0 {
		y.low ^= getUint64(blocks)
		y.high ^= getUint64(blocks[8:])
		g.mul(y)
		blocks = blocks[gcmBlockSize:]
	}
}

// update extends y with more polynomial terms from data. If data is not a
// multiple of gcmBlockSize bytes long then the remainder is zero padded.
func (g *gcm) update(y *gcmFieldElement, data []byte) {
	fullBlocks := (len(data) >> 4) << 4
	g.updateBlocks(y, data[:fullBlocks])

	if len(data) != fullBlocks {
		var partialBlock [gcmBlockSize]byte
		copy(partialBlock[:], data[fullBlocks:])
		g.updateBlocks(y, partialBlock[:])
	}
}

// gcmInc32 treats the final four bytes of counterBlock as a big-endian value
// and increments it.
func gcmInc32(counterBlock *[16]byte) {
	for i := gcmBlockSize - 1; i >= gcmBlockSize-4; i-- {
		counterBlock[i]++
		if counterBlock[i] != 0 {
			break
		}
	}
}

// counterCrypt crypts in to out using g.cipher in counter mode.
func (g *gcm) counterCrypt(out, in []byte, counter *[gcmBlockSize]byte) {
	var mask [gcmBlockSize]byte
	for len(in) >= gcmBlockSize {
		g.cipher.Encrypt(mask[:], counter[:])
		gcmInc32(counter)
		xorWords(out, in, mask[:])
		out = out[gcmBlockSize:]
		in = in[gcmBlockSize:]

	}

	if len(in) > 0 {
		g.cipher.Encrypt(mask[:], counter[:])
		gcmInc32(counter)
		XorBytes(out, in, mask[:])
	}

}

// deriveCounter computes the initial GCM counter state from the given nonce.
// See NIST SP 800-38D, section 7.1. This assumes that counter is filled with
// zeros on entry.
func (g *gcm) deriveCounter(counter *[gcmBlockSize]byte, nonce []byte) {
	// GCM has two modes of operation with respect to the initial counter
	// state: a "fast path" for 96-bit (12-byte) nonces, and a "slow path"
	// for nonces of other lengths. For a 96-bit nonce, the nonce, along
	// with a four-byte big-endian counter starting at one, is used
	// directly as the starting counter. For other nonce sizes, the counter
	// is computed by passing it through the GHASH function.
	if len(nonce) == gcmStandardNonceSize {
		copy(counter[:], nonce)
		counter[gcmBlockSize-1] = 1
	} else {
		var y gcmFieldElement
		g.update(&y, nonce)
		y.high ^= uint64(len(nonce)) * 8
		g.mul(&y)
		putUint64(counter[:8], y.low)
		putUint64(counter[8:], y.high)
	}
}

// auth calculates GHASH(ciphertext, additionalData), masks the result with
// tagMask and writes the result to out.
func (g *gcm) auth(out, ciphertext, additionalData []byte, tagMask *[gcmTagSize]byte) {
	var y gcmFieldElement
	g.update(&y, additionalData)
	g.update(&y, ciphertext)

	y.low ^= uint64(len(additionalData)) * 8
	y.high ^= uint64(len(ciphertext)) * 8

	g.mul(&y)

	putUint64(out, y.low)
	putUint64(out[8:], y.high)

	xorWords(out, out, tagMask[:])
}

func getUint64(data []byte) uint64 {
	r := uint64(data[0])<<56 |
		uint64(data[1])<<48 |
		uint64(data[2])<<40 |
		uint64(data[3])<<32 |
		uint64(data[4])<<24 |
		uint64(data[5])<<16 |
		uint64(data[6])<<8 |
		uint64(data[7])
	return r
}

func putUint64(out []byte, v uint64) {
	out[0] = byte(v >> 56)
	out[1] = byte(v >> 48)
	out[2] = byte(v >> 40)
	out[3] = byte(v >> 32)
	out[4] = byte(v >> 24)
	out[5] = byte(v >> 16)
	out[6] = byte(v >> 8)
	out[7] = byte(v)
}
