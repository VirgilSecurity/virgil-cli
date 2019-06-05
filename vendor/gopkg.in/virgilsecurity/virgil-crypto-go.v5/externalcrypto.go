/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2015-2018, Virgil Security, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package virgil_crypto_go

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/pkg/errors"
)

type ExternalCrypto struct {
	keyType               KeyType
	UseSha256Fingerprints bool
}

func NewVirgilCrypto() *ExternalCrypto {
	return &ExternalCrypto{}
}

const (
	signatureKey = "VIRGIL-DATA-SIGNATURE"
	signerId     = "VIRGIL-DATA-SIGNER-ID"
)

func (c *ExternalCrypto) SetKeyType(keyType KeyType) error {
	if _, ok := KeyTypeMap[keyType]; !ok {
		return errors.New("key type not supported")
	} else {
		c.keyType = keyType
		return nil
	}
}

func (c *ExternalCrypto) GenerateKeypair() (_ *externalKeypair, err error) {

	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	keyType, ok := KeyTypeMap[c.keyType]
	if !ok {
		return nil, errors.New("This key type is not supported")
	}

	kp := VirgilKeyPairGenerate(keyType)
	defer DeleteVirgilKeyPair(kp)

	der := VirgilKeyPairPublicKeyToDER(kp.PublicKey())
	defer DeleteVirgilByteArray(der)

	rawPub := ToSlice(der)
	receiverId := c.CalculateFingerprint(rawPub)

	pub := &externalPublicKey{
		key:        rawPub,
		receiverID: receiverId,
	}

	der1 := VirgilKeyPairPrivateKeyToDER(kp.PrivateKey())
	defer DeleteVirgilByteArray(der1)
	rawPriv := ToSlice(der1)

	priv := &externalPrivateKey{
		key:        rawPriv,
		receiverID: receiverId,
	}

	return &externalKeypair{
		publicKey:  pub,
		privateKey: priv,
	}, nil
}

func (c *ExternalCrypto) GenerateKeypairFromKeyMaterial(keyMaterial []byte) (_ *externalKeypair, err error) {

	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	keyType, ok := KeyTypeMap[c.keyType]
	if !ok {
		return nil, errors.New("This key type is not supported")
	}

	seed := ToVirgilByteArray(keyMaterial)
	defer DeleteVirgilByteArray(seed)

	kp := VirgilKeyPairGenerateFromKeyMaterial(keyType, seed)
	defer DeleteVirgilKeyPair(kp)

	der := VirgilKeyPairPublicKeyToDER(kp.PublicKey())
	defer DeleteVirgilByteArray(der)

	rawPub := ToSlice(der)
	receiverId := c.CalculateFingerprint(rawPub)

	pub := &externalPublicKey{
		key:        rawPub,
		receiverID: receiverId,
	}

	der1 := VirgilKeyPairPrivateKeyToDER(kp.PrivateKey())
	defer DeleteVirgilByteArray(der1)
	rawPriv := ToSlice(der1)

	priv := &externalPrivateKey{
		key:        rawPriv,
		receiverID: receiverId,
	}

	return &externalKeypair{
		publicKey:  pub,
		privateKey: priv,
	}, nil
}

func (c *ExternalCrypto) ImportPrivateKey(data []byte, password string) (_ interface {
	IsPrivate() bool
	Identifier() []byte
}, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()
	var rawPriv []byte

	unwrappedKey := unwrapKey(data)
	if password == "" {
		rawPriv = unwrappedKey
	} else {

		vdata := ToVirgilByteArray(unwrappedKey)
		defer DeleteVirgilByteArray(vdata)
		vpassword := ToVirgilByteArray([]byte(password))
		defer DeleteVirgilByteArray(vpassword)
		dec := VirgilKeyPairDecryptPrivateKey(vdata, vpassword)
		defer DeleteVirgilByteArray(dec)
		der := VirgilKeyPairPrivateKeyToDER(dec)
		defer DeleteVirgilByteArray(der)

		rawPriv = ToSlice(der)
	}

	vpriv := ToVirgilByteArray(rawPriv)
	defer DeleteVirgilByteArray(vpriv)
	vempty := ToVirgilByteArray(make([]byte, 0))
	defer DeleteVirgilByteArray(vempty)
	vpub := VirgilKeyPairExtractPublicKey(vpriv, vempty)
	defer DeleteVirgilByteArray(vpub)

	rawPub := ToSlice(vpub)

	receiverId := c.CalculateFingerprint(rawPub)

	return &externalPrivateKey{
		key:        rawPriv,
		receiverID: receiverId,
	}, nil
}

func (c *ExternalCrypto) ImportPublicKey(data []byte) (_ interface {
	IsPublic() bool
	Identifier() []byte
}, err error) {

	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()


	rawPub := unwrapKey(data)

	bpub := ToVirgilByteArray(rawPub)
	defer DeleteVirgilByteArray(bpub)

	derKey := VirgilKeyPairPublicKeyToDER(bpub)
	defer DeleteVirgilByteArray(derKey)

	rawPub = ToSlice(derKey)
	receiverId := c.CalculateFingerprint(rawPub)

	return &externalPublicKey{
		key:        rawPub,
		receiverID: receiverId,
	}, nil

}

func (c *ExternalCrypto) ExportPrivateKey(key interface {
	IsPrivate() bool
	Identifier() []byte
}, password string) (_ []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	return key.(*externalPrivateKey).Encode([]byte(password))
}

func (c *ExternalCrypto) ExportPublicKey(key interface {
	IsPublic() bool
	Identifier() []byte
}) (_ []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()
	return key.(*externalPublicKey).Encode()
}

func (c *ExternalCrypto) Encrypt(data []byte, recipients ...interface {
	IsPublic() bool
	Identifier() []byte
}) (_ []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	ci := NewVirgilCipher()
	defer DeleteVirgilCipher(ci)

	for _, r := range recipients {
		vrec := ToVirgilByteArray(r.Identifier())
		defer DeleteVirgilByteArray(vrec)
		vcon := ToVirgilByteArray(r.(*externalPublicKey).contents())
		defer DeleteVirgilByteArray(vcon)
		ci.AddKeyRecipient(vrec, vcon)
	}
	vdata := ToVirgilByteArray(data)
	defer DeleteVirgilByteArray(vdata)

	venc := ci.Encrypt(vdata, true)
	defer DeleteVirgilByteArray(venc)

	ct := ToSlice(venc)

	return ct, nil
}

func (c *ExternalCrypto) EncryptStream(in io.Reader, out io.Writer, recipients ...interface {
	IsPublic() bool
	Identifier() []byte
}) (err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	s := NewDirectorVirgilDataSource(NewDataSource(in))
	defer DeleteDirectorVirgilDataSource(s)

	d := NewDirectorVirgilDataSink(NewDataSink(out))
	defer DeleteDirectorVirgilDataSink(d)

	ci := NewVirgilStreamCipher()
	defer DeleteVirgilStreamCipher(ci)

	for _, r := range recipients {
		vrec := ToVirgilByteArray(r.Identifier())
		defer DeleteVirgilByteArray(vrec)

		vcon := ToVirgilByteArray(r.(*externalPublicKey).contents())
		defer DeleteVirgilByteArray(vcon)
		ci.AddKeyRecipient(vrec, vcon)

	}

	ci.Encrypt(s, d)

	return

}

func (c *ExternalCrypto) Decrypt(data []byte, key interface {
	IsPrivate() bool
	Identifier() []byte
}) (_ []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	ci := NewVirgilCipher()
	defer DeleteVirgilCipher(ci)

	vdata := ToVirgilByteArray(data)
	defer DeleteVirgilByteArray(vdata)
	vrec := ToVirgilByteArray(key.Identifier())
	defer DeleteVirgilByteArray(vrec)
	vcontents := ToVirgilByteArray(key.(*externalPrivateKey).contents())
	defer DeleteVirgilByteArray(vcontents)

	vplain := ci.DecryptWithKey(vdata, vrec, vcontents)
	defer DeleteVirgilByteArray(vplain)
	plainText := ToSlice(vplain)
	return plainText, nil
}

func (c *ExternalCrypto) DecryptStream(in io.Reader, out io.Writer, key interface {
	IsPrivate() bool
	Identifier() []byte
}) (err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	d := NewDirectorVirgilDataSink(NewDataSink(out))
	defer DeleteDirectorVirgilDataSink(d)
	s := NewDirectorVirgilDataSource(NewDataSource(in))
	defer DeleteDirectorVirgilDataSource(s)

	ci := NewVirgilStreamCipher()
	defer DeleteVirgilStreamCipher(ci)

	vcontents := ToVirgilByteArray(key.(*externalPrivateKey).contents())
	defer DeleteVirgilByteArray(vcontents)

	vrec := ToVirgilByteArray(key.(*externalPrivateKey).receiverID)
	defer DeleteVirgilByteArray(vrec)

	ci.DecryptWithKey(s, d, vrec, vcontents)

	return
}

func (c *ExternalCrypto) Sign(data []byte, signer interface {
	IsPrivate() bool
	Identifier() []byte
}) (_ []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()


	var algo interface{}
	if c.UseSha256Fingerprints{
		algo = VirgilHashAlgorithm_SHA256
	} else {
		algo = VirgilHashAlgorithm_SHA512
	}

	s := NewVirgilSigner(algo)
	defer DeleteVirgilSigner(s)
	vdata := ToVirgilByteArray(data)
	defer DeleteVirgilByteArray(vdata)
	vkey := ToVirgilByteArray(signer.(*externalPrivateKey).contents())
	defer DeleteVirgilByteArray(vkey)
	vsign := s.Sign(vdata, vkey)
	defer DeleteVirgilByteArray(vsign)

	signature := ToSlice(vsign)
	return signature, nil
}

func (c *ExternalCrypto) VerifySignature(data []byte, signature []byte, key interface {
	IsPublic() bool
	Identifier() []byte
}) (err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()
	s := NewVirgilSigner(VirgilHashAlgorithm_SHA512)
	defer DeleteVirgilSigner(s)

	vdata := ToVirgilByteArray(data)
	defer DeleteVirgilByteArray(vdata)
	vsignature := ToVirgilByteArray(signature)
	defer DeleteVirgilByteArray(vsignature)
	vcontents := ToVirgilByteArray(key.(*externalPublicKey).contents())
	defer DeleteVirgilByteArray(vcontents)

	valid := s.Verify(vdata, vsignature, vcontents)

	if !valid {
		return errors.New("invalid signature")
	}

	return nil
}


func (c *ExternalCrypto) VerifyHashTypeSignature(hashType HashType, data []byte, signature []byte, key interface {
	IsPublic() bool
	Identifier() []byte
}) (err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()
	s := NewVirgilSigner(VirgilHashAlgorithm_SHA512)
	defer DeleteVirgilSigner(s)

	hdata := ToVirgilByteArray(data)
	defer DeleteVirgilByteArray(hdata)
	vsignature := ToVirgilByteArray(signature)
	defer DeleteVirgilByteArray(vsignature)
	vcontents := ToVirgilByteArray(key.(*externalPublicKey).contents())
	defer DeleteVirgilByteArray(vcontents)

	valid := s.Verify(hdata, vsignature, vcontents)

	if !valid {
		return errors.New("invalid signature")
	}

	algo := s.GetHashAlgorithm()
	if hashType != HashType(algo){
		return errors.New("unsupported signature hash type")
	}

	return nil
}

func (c *ExternalCrypto) SignStream(in io.Reader, signerKey interface {
	IsPrivate() bool
	Identifier() []byte
}) (_ []byte, err error) {

	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	signer := NewVirgilStreamSigner(VirgilHashAlgorithm_SHA512)
	defer DeleteVirgilStreamSigner(signer)

	s := NewDirectorVirgilDataSource(NewDataSource(in))
	defer DeleteDirectorVirgilDataSource(s)

	vcontents := ToVirgilByteArray(signerKey.(*externalPrivateKey).contents())
	defer DeleteVirgilByteArray(vcontents)

	vsign := signer.Sign(s, vcontents)
	defer DeleteVirgilByteArray(vsign)

	return ToSlice(vsign), nil
}

func (c *ExternalCrypto) VerifyStream(in io.Reader, signature []byte, key interface {
	IsPublic() bool
	Identifier() []byte
}) (res bool, err error) {

	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	signer := NewVirgilStreamSigner(VirgilHashAlgorithm_SHA512)
	defer DeleteVirgilStreamSigner(signer)

	s := NewDirectorVirgilDataSource(NewDataSource(in))
	defer DeleteDirectorVirgilDataSource(s)

	vsign := ToVirgilByteArray(signature)
	defer DeleteVirgilByteArray(vsign)

	vcontents := ToVirgilByteArray(key.(*externalPublicKey).contents())
	defer DeleteVirgilByteArray(vcontents)

	res = signer.Verify(s, vsign, vcontents)

	return res, nil
}
func (c *ExternalCrypto) CalculateFingerprint(data []byte) []byte {
	if c.UseSha256Fingerprints {
		hash := sha256.Sum256(data)
		return hash[:]
	} else {
		hash := sha512.Sum512(data)
		return hash[:8]
	}
}

func (c *ExternalCrypto) SignThenEncrypt(data []byte, signerKey interface {
	IsPrivate() bool
	Identifier() []byte
}, recipients ...interface {
	IsPublic() bool
	Identifier() []byte
}) (_ []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()
	ci := NewVirgilCipher()
	defer DeleteVirgilCipher(ci)
	params := ci.CustomParams().(VirgilCustomParams)

	signature, err := c.Sign(data, signerKey)
	if err != nil {
		return nil, err
	}
	vsigKey := ToVirgilByteArray([]byte(signatureKey))
	defer DeleteVirgilByteArray(vsigKey)

	vsig := ToVirgilByteArray(signature)
	defer DeleteVirgilByteArray(vsig)
	params.SetData(vsigKey, vsig)

	vsignerKey := ToVirgilByteArray([]byte(signerId))
	defer DeleteVirgilByteArray(vsignerKey)
	vsigner := ToVirgilByteArray(signerKey.Identifier())
	defer DeleteVirgilByteArray(vsigner)
	params.SetData(vsignerKey, vsigner)

	for _, r := range recipients {

		vrec := ToVirgilByteArray(r.Identifier())
		defer DeleteVirgilByteArray(vrec)
		vconts := ToVirgilByteArray(r.(*externalPublicKey).contents())
		defer DeleteVirgilByteArray(vconts)
		ci.AddKeyRecipient(vrec, vconts)
	}

	vdata := ToVirgilByteArray(data)
	defer DeleteVirgilByteArray(vdata)
	venc := ci.Encrypt(vdata, true)
	defer DeleteVirgilByteArray(venc)
	ct := ToSlice(venc)

	return ct, nil
}

func (c *ExternalCrypto) DecryptThenVerify(data []byte, decryptionKey interface {
	IsPrivate() bool
	Identifier() []byte
}, verifierKeys ...interface {
	IsPublic() bool
	Identifier() []byte
}) (_ []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	ci := NewVirgilCipher()
	defer DeleteVirgilCipher(ci)

	vdata := ToVirgilByteArray(data)
	defer DeleteVirgilByteArray(vdata)
	vrec := ToVirgilByteArray(decryptionKey.Identifier())
	defer DeleteVirgilByteArray(vrec)
	vkey := ToVirgilByteArray(decryptionKey.(*externalPrivateKey).key)
	defer DeleteVirgilByteArray(vkey)
	vpt := ci.DecryptWithKey(vdata, vrec, vkey)
	defer DeleteVirgilByteArray(vpt)

	plaintext := ToSlice(vpt)

	vsigKey := ToVirgilByteArray([]byte(signatureKey))
	defer DeleteVirgilByteArray(vsigKey)
	sigString := ci.CustomParams().(VirgilCustomParams).GetData(vsigKey)
	defer DeleteVirgilByteArray(sigString)

	sig := ToSlice(sigString)

	if len(verifierKeys) == 1 {
		err := c.VerifySignature(plaintext, sig, verifierKeys[0])
		if err != nil {
			return nil, err
		}

	} else {
		vsignerIdKey := ToVirgilByteArray([]byte(signerId))
		defer DeleteVirgilByteArray(vsignerIdKey)
		signerIdString := ci.CustomParams().(VirgilCustomParams).GetData(vsignerIdKey)
		defer DeleteVirgilByteArray(signerIdString)

		signerIdValue := ToSlice(signerIdString)

		for _, v := range verifierKeys {

			if subtle.ConstantTimeCompare(v.Identifier(), signerIdValue) == 1 {
				err := c.VerifySignature(plaintext, sig, v)
				if err != nil {
					return nil, err
				}
				return plaintext, nil
			}
		}
		return nil, errors.New("Could not verify signature with provided keys")

	}

	return plaintext, nil
}

func (c *ExternalCrypto) ExtractPublicKey(key interface {
	IsPrivate() bool
	Identifier() []byte
}) (_ interface {
	IsPublic() bool
	Identifier() []byte
}, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	return key.(*externalPrivateKey).ExtractPublicKey()

}

//ToSlice converts VirgilByteArray to a go slice
func ToSlice(b VirgilByteArray) []byte {
	l := int(b.Size())
	res := make([]byte, l)
	for i := 0; i < l; i++ {
		res[i] = b.Get(i)
	}
	return res
}

//ToVirgilByteArray converts go slice to a VirgilByteArray
func ToVirgilByteArray(data []byte) VirgilByteArray {
	l := len(data)
	b := NewVirgilByteArray(uint(len(data)))
	for i := 0; i < l; i++ {
		b.Set(i, data[i])
	}
	return b
}
