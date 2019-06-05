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

	"crypto/sha512"

	"github.com/minio/sha256-simd"
	"gopkg.in/virgil.v5/cryptoimpl/keytypes"
	"gopkg.in/virgil.v5/errors"
)

type (
	VirgilCrypto struct {
		MakeCipher            func() Cipher
		UseSHA256Fingerprints bool
	}
)

func NewVirgilCrypto() *VirgilCrypto {
	return &VirgilCrypto{}
}

func (c *VirgilCrypto) SetKeyType(keyType KeyType) error {
	if keyType != keytypes.Default && keyType != keytypes.FAST_EC_ED25519 {
		return errors.New("Only ED25519 keys are supported")
	}
	return nil
}

func (c *VirgilCrypto) GenerateKeypair() (*ed25519Keypair, error) {

	keypair, err := NewKeypair()
	return keypair, err
}

func (c *VirgilCrypto) ImportPrivateKey(data []byte, password string) (interface {
	IsPrivate() bool
	Identifier() []byte
}, error) {
	key, err := DecodePrivateKey(data, []byte(password))
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (c *VirgilCrypto) ImportPublicKey(data []byte) (interface {
	IsPublic() bool
	Identifier() []byte
}, error) {
	key, err := DecodePublicKey(data)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (c *VirgilCrypto) ExportPrivateKey(key interface {
	IsPrivate() bool
	Identifier() []byte
}, password string) ([]byte, error) {
	if key == nil {
		return nil, errors.New("key is nil")
	}
	return key.(*ed25519PrivateKey).Encode([]byte(password))
}

func (c *VirgilCrypto) ExportPublicKey(key interface {
	IsPublic() bool
	Identifier() []byte
}) ([]byte, error) {
	if key == nil {
		return nil, errors.New("key is nil")
	}
	return key.(*ed25519PublicKey).Encode()
}

func (c *VirgilCrypto) Encrypt(data []byte, recipients ...interface {
	IsPublic() bool
	Identifier() []byte
}) ([]byte, error) {
	cipher := c.getCipher()
	for _, k := range recipients {
		if k == nil {
			return nil, errors.New("key is nil")
		}
		if err := cipher.AddKeyRecipient(k.(*ed25519PublicKey)); err != nil {
			return nil, err
		}

	}
	return cipher.Encrypt(data)
}

func (c *VirgilCrypto) EncryptStream(in io.Reader, out io.Writer, recipients ...interface {
	IsPublic() bool
	Identifier() []byte
}) error {
	cipher := c.getCipher()
	for _, k := range recipients {
		if k == nil {
			return errors.New("key is nil")
		}
		if err := cipher.AddKeyRecipient(k.(*ed25519PublicKey)); err != nil {
			return err
		}
	}
	return cipher.EncryptStream(in, out)
}

func (c *VirgilCrypto) Decrypt(data []byte, key interface {
	IsPrivate() bool
	Identifier() []byte
}) ([]byte, error) {
	if key == nil {
		return nil, errors.New("key is nil")
	}
	return c.getCipher().DecryptWithPrivateKey(data, key.(*ed25519PrivateKey))
}

func (c *VirgilCrypto) DecryptStream(in io.Reader, out io.Writer, key interface {
	IsPrivate() bool
	Identifier() []byte
}) error {
	if key == nil {
		return errors.New("key is nil")
	}
	return c.getCipher().DecryptStream(in, out, key.(*ed25519PrivateKey))
}

func (c *VirgilCrypto) Sign(data []byte, key interface {
	IsPrivate() bool
	Identifier() []byte
}) ([]byte, error) {
	if key == nil {
		return nil, errors.New("key is nil")
	}

	var hash []byte

	if c.UseSHA256Fingerprints {
		tmp := sha256.Sum256(data)
		hash = tmp[:]
	} else {
		tmp := sha512.Sum512(data)
		hash = tmp[:]
	}

	return Signer.SignHash(hash, key.(*ed25519PrivateKey))
}

func (c *VirgilCrypto) VerifySignature(data []byte, signature []byte, key interface {
	IsPublic() bool
	Identifier() []byte
}) error {
	if key == nil {
		return errors.New("key is nil")
	}
	return Verifier.Verify(data, key.(*ed25519PublicKey), signature)
}

func (c *VirgilCrypto) VerifyHashSignature(hash []byte, signature []byte, key interface {
	IsPublic() bool
	Identifier() []byte
}) error {
	if key == nil {
		return errors.New("key is nil")
	}
	return Verifier.VerifyHash(hash, key.(*ed25519PublicKey), signature)
}

func (c *VirgilCrypto) SignStream(in io.Reader, key interface {
	IsPrivate() bool
	Identifier() []byte
}) ([]byte, error) {
	if key == nil {
		return nil, errors.New("key is nil")
	}
	res, err := Signer.SignStream(in, key.(*ed25519PrivateKey))
	if err != nil {
		return nil, err
	}
	return []byte(res), nil
}

func (c *VirgilCrypto) VerifyStream(in io.Reader, signature []byte, key interface {
	IsPublic() bool
	Identifier() []byte
}) error {
	if key == nil {
		return errors.New("key is nil")
	}
	return Verifier.VerifyStream(in, key.(*ed25519PublicKey), signature)
}

func (c *VirgilCrypto) CalculateIdentifier(data []byte) []byte {
	var hash []byte
	if c.UseSHA256Fingerprints {
		t := sha256.Sum256(data)
		hash = t[:]
	} else {
		hash = calculateSHA512BasedIdentifier(data)
	}
	return hash
}

func (c *VirgilCrypto) SignThenEncrypt(data []byte, signerKey interface {
	IsPrivate() bool
	Identifier() []byte
}, recipients ...interface {
	IsPublic() bool
	Identifier() []byte
}) ([]byte, error) {

	if signerKey == nil {
		return nil, errors.New("key is nil")
	}
	cipher := c.getCipher()
	for _, k := range recipients {
		if err := cipher.AddKeyRecipient(k.(*ed25519PublicKey)); err != nil {
			return nil, err
		}
	}
	return cipher.SignThenEncrypt(data, signerKey.(*ed25519PrivateKey))
}

func (c *VirgilCrypto) DecryptThenVerify(data []byte, decryptionKey interface {
	IsPrivate() bool
	Identifier() []byte
}, verifierKeys ...interface {
	IsPublic() bool
	Identifier() []byte
}) ([]byte, error) {
	if decryptionKey == nil || len(verifierKeys) == 0 {
		return nil, errors.New("key is nil")
	}

	verifiers := make([]*ed25519PublicKey, 0, len(verifierKeys))
	for _, v := range verifierKeys {
		if key, ok := v.(interface {
			IsPublic() bool
			Identifier() []byte
		}); ok {
			verifiers = append(verifiers, key.(*ed25519PublicKey))
		} else {
			return nil, errors.New("key type is not supported")
		}

	}

	return c.getCipher().DecryptThenVerify(data, decryptionKey.(*ed25519PrivateKey), verifiers...)
}

func (c *VirgilCrypto) ExtractPublicKey(key interface {
	IsPrivate() bool
	Identifier() []byte
}) (interface {
	IsPublic() bool
	Identifier() []byte
}, error) {
	if key == nil {
		return nil, errors.New("key is nil")
	}
	return key.(*ed25519PrivateKey).ExtractPublicKey()
}

func (c *VirgilCrypto) getCipher() Cipher {
	if c.MakeCipher != nil {
		return c.MakeCipher()
	}
	return NewCipher()
}

func calculateSHA512BasedIdentifier(data []byte) []byte {
	t := sha512.Sum512(data)
	return t[:8]
}
