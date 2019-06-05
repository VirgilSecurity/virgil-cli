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

package sdk

import (
	"gopkg.in/virgil.v5/cryptoapi"
	"gopkg.in/virgil.v5/errors"
)

type VirgilPrivateKeyStorage struct {
	PrivateKeyExporter cryptoapi.PrivateKeyExporter
	KeyStorage         KeyStorage
}

func NewVirgilPrivateKeyStorage(privateKeyExporter cryptoapi.PrivateKeyExporter, path string) cryptoapi.PrivateKeyStorage {

	return &VirgilPrivateKeyStorage{
		PrivateKeyExporter: privateKeyExporter,
		KeyStorage: &FileKeyStorage{
			RootDir: path,
		},
	}
}

func (v *VirgilPrivateKeyStorage) Store(key interface {
	IsPrivate() bool
	Identifier() []byte
}, name string, meta map[string]string) error {

	if v.PrivateKeyExporter == nil {
		return errors.New("PrivateKeyExporter is not set")
	}

	if v.KeyStorage == nil {
		return errors.New("KeyStorage is not set")
	}

	exported, err := v.PrivateKeyExporter.ExportPrivateKey(key)

	if err != nil {
		return err
	}

	return v.KeyStorage.Store(&StorageItem{
		Name: name,
		Data: exported,
		Meta: meta,
	})

}

func (v *VirgilPrivateKeyStorage) Load(name string) (key interface {
	IsPrivate() bool
	Identifier() []byte
}, meta map[string]string, err error) {
	if v.PrivateKeyExporter == nil {
		err = errors.New("PrivateKeyExporter is not set")
		return
	}

	if v.KeyStorage == nil {
		err = errors.New("KeyStorage is not set")
		return
	}

	item, err := v.KeyStorage.Load(name)

	if err != nil {
		return
	}

	key, err = v.PrivateKeyExporter.ImportPrivateKey(item.Data)
	if err != nil {
		return
	}

	return key, item.Meta, nil
}

func (v *VirgilPrivateKeyStorage) Delete(name string) error {
	if v.KeyStorage == nil {
		return errors.New("KeyStorage is not set")
	}

	return v.KeyStorage.Delete(name)
}
