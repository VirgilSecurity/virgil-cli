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
	"crypto/x509/pkix"
	"encoding/asn1"
	"math"

	"gopkg.in/virgil.v5/errors"
)

var (
	oidAesGCM         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}
	oidData           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidAES256CBC      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	OidSha256         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OidSha384         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OidSha512         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidKdf2           = asn1.ObjectIdentifier{1, 0, 18033, 2, 5, 2}
	oidEnvelopedData  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidHmacWithSha384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHmacWithSha512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	oidPbkdf2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidPbeS2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}

	oidEd25519key = asn1.ObjectIdentifier{1, 3, 101, 112}
)

//ASN.1 structures

var asn1Null = asn1.RawValue{Tag: 5} /*NULL*/

type algorithmIdentifierWithOidParameter struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.ObjectIdentifier `asn1:"optional"`
}

var ed25519Algo = pkix.AlgorithmIdentifier{
	Algorithm:  oidEd25519key,
	Parameters: asn1Null,
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters []byte `asn1:"optional"`
}

type encryptedData struct {
	CipherParams algorithmIdentifier
	Value        []byte
}
type Envelope struct {
	Version      int
	Data         CMSEnvelope
	CustomParams []CustomParam `asn1:"set,explicit,optional"`
}

type CustomParam struct {
	Key   string        `asn1:"utf8"`
	Value asn1.RawValue //`asn1:"explicit"`
}

type CMSEnvelope struct {
	ContentType asn1.ObjectIdentifier
	Content     envelopedData `asn1:"tag:0,explicit"`
}

//we keep nonce here
type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm algorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional,explicit"`
}

type envelopedData struct {
	Version              int
	RecipientInfos       asn1.RawValue // array of PublicKeyRecipientInfo & PasswordRecipientInfo
	EncryptedContentInfo encryptedContentInfo
}
type issuerAndSerial []byte

type publicKeyRecipientInfo struct {
	Version                int
	RecipientID            issuerAndSerial `asn1:"tag:0,explicit"`
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte //serialized EncryptedKeyWithPublicKey
}

type encryptedKeyWithPublicKey struct {
	Version       int
	PublicKey     publicKeyDescription
	KdfAlgo       kdfAlgorithm
	Hmac          hmacInfo
	EncryptedData encryptedData
}

type kdfAlgorithm struct {
	Oid      asn1.ObjectIdentifier
	HashAlgo pkix.AlgorithmIdentifier
}
type publicKeyDescription struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type hmacInfo struct {
	HmacAlgo pkix.AlgorithmIdentifier
	Value    []byte
}

type pkdf2Params struct {
	Salt            []byte
	IterationsCount int
	Prf             algorithmIdentifier
}

type pbeS2Parameters struct {
	KeyDerivationFunc pkix.AlgorithmIdentifier
	EncryptionScheme  algorithmIdentifier
}

type passwordRecipientInfo struct {
	Version                int
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type signature struct {
	O pkix.AlgorithmIdentifier
	S []byte
}

//keys

type privateKeyAsn struct {
	Version    int
	OID        pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type publicKey struct {
	Algorithm algorithmIdentifierWithOidParameter
	Key       asn1.BitString
}

type envelopeKey struct {
	Algorithm  pkix.AlgorithmIdentifier
	CipherText []byte
}

type validator interface {
	Validate() error
}

func makePublicKeyRecipient(id []byte, publicKey []byte, mac []byte, key []byte, keyIv []byte) (*asn1.RawValue, error) {

	encryptedKey := encryptedData{
		CipherParams: algorithmIdentifier{
			Algorithm:  oidAES256CBC,
			Parameters: keyIv,
		},
		Value: key,
	}
	hmac := hmacInfo{
		HmacAlgo: pkix.AlgorithmIdentifier{
			Algorithm:  OidSha512,
			Parameters: asn1Null,
		},
		Value: mac,
	}
	kdf := kdfAlgorithm{
		Oid: oidKdf2,
		HashAlgo: pkix.AlgorithmIdentifier{
			Algorithm:  OidSha512,
			Parameters: asn1Null,
		},
	}

	pk := publicKeyDescription{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidEd25519key},
		PublicKey: asn1.BitString{Bytes: publicKey},
	}

	content := encryptedKeyWithPublicKey{
		Version:       0,
		PublicKey:     pk,
		KdfAlgo:       kdf,
		Hmac:          hmac,
		EncryptedData: encryptedKey,
	}
	contentBytes, err := asn1.Marshal(content)
	if err != nil {
		return nil, cryptoError(err, "")
	}

	recipient := publicKeyRecipientInfo{
		Version:                2,
		RecipientID:            []byte(id),
		KeyEncryptionAlgorithm: ed25519Algo,
		EncryptedKey:           contentBytes,
	}

	raw, err := asn1.Marshal(recipient)
	if err != nil {
		return nil, cryptoError(err, "")
	}

	return &asn1.RawValue{
		FullBytes: raw,
	}, nil

}
func makePasswordRecipient(kdfIv []byte, iterations int, key, keyIv []byte) (*asn1.RawValue, error) {

	keyEncryptionAlgorithm, err := encodeKeyEncryptionAlgorithm(kdfIv, iterations, keyIv)

	if err != nil {
		return nil, err
	}
	recipient := passwordRecipientInfo{
		Version:                0,
		KeyEncryptionAlgorithm: *keyEncryptionAlgorithm,
		EncryptedKey:           key,
	}

	recBytes, err := asn1.Marshal(recipient)
	if err != nil {
		return nil, cryptoError(err, "")
	}
	res := &asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        3,
		Bytes:      recBytes,
		IsCompound: true,
	}

	return res, nil
}
func makeSignature(sign []byte, hashSize int) ([]byte, error) {

	var algo asn1.ObjectIdentifier

	switch hashSize {
	case 32:
		algo = OidSha256
		break
	case 48:
		algo = OidSha384
		break
	case 64:
		algo = OidSha512
		break
	default:
		return nil, CryptoError("unsupported hash")
	}

	signature := signature{O: pkix.AlgorithmIdentifier{Algorithm: algo, Parameters: asn1Null}, S: sign}
	sBytes, err := asn1.Marshal(signature)
	if err != nil {
		return nil, cryptoError(err, "")
	}
	return sBytes, nil
}
func decodeSignature(signatureBytes []byte) ([]byte, *asn1.ObjectIdentifier, error) {

	signature := &signature{}

	_, err := asn1.Unmarshal(signatureBytes, signature)
	if err != nil {
		return nil, nil, cryptoError(err, "")

	}

	parsedAlgo := signature.O.Algorithm
	var algo *asn1.ObjectIdentifier

	if parsedAlgo.Equal(OidSha384) {
		algo = &OidSha384
	} else if parsedAlgo.Equal(OidSha512) {
		algo = &OidSha512
	} else {
		return nil, nil, cryptoError(errors.New("unsupported signature hash"), "")
	}

	return signature.S, algo, nil
}
func composeCMSMessage(nonce []byte, recipients []*asn1.RawValue, customParams map[string]interface{}) (resBytes []byte, err error) {

	ciphertextInfo := encryptedContentInfo{
		ContentType: oidData,
		ContentEncryptionAlgorithm: algorithmIdentifier{
			Algorithm:  oidAesGCM,
			Parameters: nonce,
		},
	}

	var serializedRecipients []byte
	for _, r := range recipients {
		serializedRecipient, err := asn1.Marshal(*r)
		if err != nil {
			return nil, cryptoError(err, "")
		}
		serializedRecipients = append(serializedRecipients, serializedRecipient...)

	}

	rawRecipients := asn1.RawValue{
		IsCompound: true,
		Tag:        asn1.TagSet,
		Bytes:      serializedRecipients,
	}

	envelopedDataModel := envelopedData{
		EncryptedContentInfo: ciphertextInfo,
		RecipientInfos:       rawRecipients,
		Version:              2,
	}
	envelopeModel := CMSEnvelope{
		ContentType: oidEnvelopedData,
		Content:     envelopedDataModel,
	}

	res := Envelope{
		Version: 0,
		Data:    envelopeModel,
	}

	if len(customParams) > 0 {

		params := make([]CustomParam, 0)
		for k, v := range customParams {
			param, err := makeParam(k, v)
			if err != nil {
				return nil, cryptoError(err, "")
			}
			params = append(params, param)
		}

		res.CustomParams = params
	}

	resBytes, err = asn1.Marshal(res)
	if err != nil {
		return nil, cryptoError(err, "")
	}
	return resBytes, nil
}
func makeParam(key string, v interface{}) (CustomParam, error) {
	asnValue, err := asn1.Marshal(v)
	if err != nil {
		return CustomParam{}, cryptoError(err, "")
	}

	tag := 0
	switch v.(type) {
	case []byte:
		tag = 2
		break
	case string:
		tag = 1
	}

	param := CustomParam{
		Key:   key,
		Value: asn1.RawValue{Bytes: asnValue, Tag: tag, IsCompound: true, Class: 2},
	}
	return param, nil

}
func decodeCMSMessage(data []byte) (customParams map[string]interface{}, ciphertext, nonce []byte, recipients []recipient, err error) {

	envelope := &Envelope{}
	if ciphertext, err = asn1.Unmarshal(data, envelope); err != nil {
		return
	}

	if err = envelope.Validate(); err != nil {
		return
	}

	content := envelope.Data.Content

	if err = content.Validate(); err != nil {
		return
	}

	if recipients, err = decodeRecipients(&content.RecipientInfos); err != nil {
		return
	}

	nonce = content.EncryptedContentInfo.ContentEncryptionAlgorithm.Parameters

	if len(envelope.CustomParams) > 0 {
		customParams = make(map[string]interface{})
		for _, e := range envelope.CustomParams {
			value, er := decodeParam(e.Value)
			if er != nil {
				err = er
				return
			}
			customParams[e.Key] = value
		}
	}

	return
}

func decodeParam(value asn1.RawValue) (interface{}, error) {

	_, er := asn1.Unmarshal(value.Bytes, &value)
	if er != nil {
		return nil, er
	}

	var v interface{}

	switch value.Tag {
	case asn1.TagInteger:
		var tmp int
		v = &tmp
	case asn1.TagOctetString:
		var tmp []byte
		v = &tmp

	}

	_, err := asn1.Unmarshal(value.FullBytes, v)
	return v, err
}

func decodeRecipients(value *asn1.RawValue) (models []recipient, err error) {
	bytes := value.Bytes
	numElements := 0
	var values []*asn1.RawValue
	for offset := 0; offset < len(bytes); {
		var t tagAndLength
		initOffset := offset
		t, offset, err = parseTagAndLength(bytes, offset)
		if err != nil {
			return
		}

		if invalidLength(offset, t.length, len(bytes)) {
			return nil, SyntaxError{"truncated sequence"}
		}

		values = append(values, &asn1.RawValue{
			Class:      t.class,
			Tag:        t.tag,
			IsCompound: t.isCompound,
			Bytes:      bytes[offset : offset+t.length],
			FullBytes:  bytes[initOffset : offset+t.length]})

		offset += t.length
		numElements++
	}

	for _, v := range values {

		var recipient recipient
		switch v.Tag {
		case 3:
			recipient, err = decodePasswordRecipient(v)
		case 16:
			recipient, err = decodeKeyRecipient(v)
		default:
			err = unsupported("recipient type")
		}
		if err == nil {
			models = append(models, recipient)
		}
	}

	if len(models) == 0 {
		return nil, CryptoError("No valid recipients found")
	}

	return models, nil
}
func decodeKeyRecipient(value *asn1.RawValue) (recipient, error) {
	recipient := &publicKeyRecipientInfo{}
	_, err := asn1.Unmarshal(value.FullBytes, recipient)
	if err != nil {
		return nil, cryptoError(err, "")
	}
	if err = recipient.Validate(); err != nil {
		return nil, err
	}

	encryptedKey := &encryptedKeyWithPublicKey{}
	_, err = asn1.Unmarshal(recipient.EncryptedKey, encryptedKey)

	if err != nil {
		return nil, cryptoError(err, "")
	}

	if err = encryptedKey.Validate(); err != nil {
		return nil, err
	}

	publicKey := encryptedKey.PublicKey.PublicKey.Bytes

	return &publicKeyRecipient{
		ID:           recipient.RecipientID,
		encryptedKey: encryptedKey.EncryptedData.Value,
		tag:          encryptedKey.Hmac.Value,
		iv:           encryptedKey.EncryptedData.CipherParams.Parameters,
		PublicKey:    publicKey,
	}, nil
}
func decodePasswordRecipient(value *asn1.RawValue) (recipient, error) {
	recipient := &passwordRecipientInfo{}
	_, err := asn1.Unmarshal(value.Bytes, recipient)
	if err != nil {
		return nil, cryptoError(err, "")
	}
	if err = recipient.Validate(); err != nil {
		return nil, err
	}

	algo := recipient.KeyEncryptionAlgorithm

	keyIv, kdfIv, iterations, err := decodeKeyEncryptionAlgorithm(&algo)
	if err != nil {
		return nil, err
	}
	return &passwordRecipient{
		encryptedKey: recipient.EncryptedKey,
		keyIv:        keyIv,
		kdfIv:        kdfIv,
		iterations:   iterations,
	}, nil
}

func encodeKeyEncryptionAlgorithm(kdfIv []byte, iterations int, keyIv []byte) (*pkix.AlgorithmIdentifier, error) {
	keyDerivationParameters := pkdf2Params{Salt: kdfIv,
		IterationsCount: iterations,
		Prf:             algorithmIdentifier{Algorithm: oidHmacWithSha512},
	}

	serializedKeyDerivationParameters, err := asn1.Marshal(keyDerivationParameters)

	if err != nil {
		return nil, cryptoError(err, "")
	}

	keyDerivationFunc := pkix.AlgorithmIdentifier{
		Algorithm:  oidPbkdf2,
		Parameters: asn1.RawValue{FullBytes: serializedKeyDerivationParameters},
	}

	scheme := algorithmIdentifier{
		Algorithm:  oidAES256CBC,
		Parameters: keyIv,
	}

	keyEncryptionParameters := pbeS2Parameters{
		KeyDerivationFunc: keyDerivationFunc,
		EncryptionScheme:  scheme,
	}

	serializedKeyEncryptionParameters, err := asn1.Marshal(keyEncryptionParameters)
	if err != nil {
		return nil, cryptoError(err, "")
	}
	return &pkix.AlgorithmIdentifier{
		Algorithm:  oidPbeS2,
		Parameters: asn1.RawValue{FullBytes: serializedKeyEncryptionParameters},
	}, nil
}

func decodeKeyEncryptionAlgorithm(alg *pkix.AlgorithmIdentifier) (keyIv, kdfIv []byte, iterations int, err error) {
	keyParams := &pbeS2Parameters{}

	algo := *alg

	_, err = asn1.Unmarshal(algo.Parameters.FullBytes, keyParams)
	if err != nil {
		err = cryptoError(err, "")
		return
	}
	if err = keyParams.Validate(); err != nil {
		return
	}

	keyIv = keyParams.EncryptionScheme.Parameters

	kdfParams := &pkdf2Params{}

	_, err = asn1.Unmarshal(keyParams.KeyDerivationFunc.Parameters.FullBytes, kdfParams)
	if err != nil {
		err = cryptoError(err, "")
		return
	}

	if err = kdfParams.Validate(); err != nil {
		return
	}
	kdfIv = kdfParams.Salt
	iterations = kdfParams.IterationsCount
	return
}

//utility functions copied from asn.1 go implementation, they are tested

// A StructuralError suggests that the ASN.1 data is valid, but the Go type
// which is receiving it doesn't match.
type StructuralError struct {
	Msg string
}

func (e StructuralError) Error() string {
	return "asn1: structure error: " + e.Msg
}

// A SyntaxError suggests that the ASN.1 data is invalid.
type SyntaxError struct {
	Msg string
}

func (e SyntaxError) Error() string {
	return "asn1: syntax error: " + e.Msg
}

type tagAndLength struct {
	class, tag, length int
	isCompound         bool
}

func invalidLength(offset, length, sliceLength int) bool {
	return offset+length < offset || offset+length > sliceLength
}

// parseBase128Int parses a base-128 encoded int from the given offset in the
// given byte slice. It returns the value and the new offset.
func parseBase128Int(bytes []byte, initOffset int) (ret, offset int, err error) {
	offset = initOffset
	var ret64 int64
	for shifted := 0; offset < len(bytes); shifted++ {
		// 5 * 7 bits per byte == 35 bits of data
		// Thus the representation is either non-minimal or too large for an int32
		if shifted == 5 {
			err = StructuralError{"base 128 integer too large"}
			return
		}
		ret64 <<= 7
		b := bytes[offset]
		ret64 |= int64(b & 0x7f)
		offset++
		if b&0x80 == 0 {
			ret = int(ret64)
			// Ensure that the returned value fits in an int on all platforms
			if ret64 > math.MaxInt32 {
				err = StructuralError{"base 128 integer too large"}
			}
			return
		}
	}
	err = SyntaxError{"truncated base 128 integer"}
	return
}

// parseTagAndLength parses an ASN.1 tag and length pair from the given offset
// into a byte slice. It returns the parsed data and the new offset. SET and
// SET OF (tag 17) are mapped to SEQUENCE and SEQUENCE OF (tag 16) since we
// don't distinguish between ordered and unordered objects in this code.
func parseTagAndLength(bytes []byte, initOffset int) (ret tagAndLength, offset int, err error) {
	offset = initOffset
	// parseTagAndLength should not be called without at least a single
	// byte to read. Thus this check is for robustness:
	if offset >= len(bytes) {
		err = errors.New("asn1: internal error in parseTagAndLength")
		return
	}
	b := bytes[offset]
	offset++
	ret.class = int(b >> 6)
	ret.isCompound = b&0x20 == 0x20
	ret.tag = int(b & 0x1f)

	// If the bottom five bits are set, then the tag number is actually base 128
	// encoded afterwards
	if ret.tag == 0x1f {
		ret.tag, offset, err = parseBase128Int(bytes, offset)
		if err != nil {
			return
		}
		// Tags should be encoded in minimal form.
		if ret.tag < 0x1f {
			err = SyntaxError{"non-minimal tag"}
			return
		}
	}
	if offset >= len(bytes) {
		err = SyntaxError{"truncated tag or length"}
		return
	}
	b = bytes[offset]
	offset++
	if b&0x80 == 0 {
		// The length is encoded in the bottom 7 bits.
		ret.length = int(b & 0x7f)
	} else {
		// Bottom 7 bits give the number of length bytes to follow.
		numBytes := int(b & 0x7f)
		if numBytes == 0 {
			err = SyntaxError{"indefinite length found (not DER)"}
			return
		}
		ret.length = 0
		for i := 0; i < numBytes; i++ {
			if offset >= len(bytes) {
				err = SyntaxError{"truncated tag or length"}
				return
			}
			b = bytes[offset]
			offset++
			if ret.length >= 1<<23 {
				// We can't shift ret.length up without
				// overflowing.
				err = StructuralError{"length too large"}
				return
			}
			ret.length <<= 8
			ret.length |= int(b)
			if ret.length == 0 {
				// DER requires that lengths be minimal.
				err = StructuralError{"superfluous leading zeros in length"}
				return
			}
		}
		// Short lengths must be encoded in short form.
		if ret.length < 0x80 {
			err = StructuralError{"non-minimal length"}
			return
		}
	}

	return
}
