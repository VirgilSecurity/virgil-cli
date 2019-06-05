/*
 * Copyright (C) 2015-2018 Virgil Security Inc.
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

package purekit

import (
	"fmt"
	"runtime"

	"github.com/VirgilSecurity/virgil-phe-go"

	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
)

const (
	// Version represents pureKit SDK version
	Version = "v2"
	header  = "purekit;go;%s;%s"
)

//MarshalRecord serializes enrolment record to protobuf
func MarshalRecord(version uint32, rec []byte) ([]byte, error) {
	if version < 1 {
		return nil, errors.New("invalid version")
	}
	dbRec := &DatabaseRecord{
		Version: version,
		Record:  rec,
	}

	return proto.Marshal(dbRec)
}

//UnmarshalRecord deserializes record from protobuf
func UnmarshalRecord(record []byte) (version uint32, rec []byte, err error) {

	dbRecord := &DatabaseRecord{}
	err = proto.Unmarshal(record, dbRecord)

	if err != nil {
		return 0, nil, errors.Wrap(err, "invalid db record")
	}

	if int(dbRecord.Version) < 1 {
		return 0, nil, errors.New("invalid record version")
	}

	return dbRecord.Version, dbRecord.Record, nil
}

func (m *HttpError) Error() string {
	return fmt.Sprintf("%s", m.Message)
}

//UpdateEnrollmentRecord increments record version and updates it using provided update token
//It returns nil record if versions match
func UpdateEnrollmentRecord(oldRecord []byte, updateToken string) (newRecord []byte, err error) {
	recordVersion, record, err := UnmarshalRecord(oldRecord)
	if err != nil {
		return nil, errors.Wrap(err, "invalid record")
	}
	tokenVersion, token, err := ParseVersionAndContent("UT", updateToken)
	if err != nil {
		return nil, errors.Wrap(err, "invalid update token")
	}
	if (recordVersion + 1) == tokenVersion {
		newRec, err := phe.UpdateRecord(record, token)
		if err != nil {
			return nil, err
		}
		return MarshalRecord(tokenVersion, newRec)
	}

	if recordVersion == tokenVersion {
		return nil, nil
	}

	return nil, errors.Errorf("Record and update token versions mismatch: %d and %d", recordVersion, tokenVersion)
}

func getAgentHeader() string {
	return fmt.Sprintf(header, runtime.GOOS, Version)
}
