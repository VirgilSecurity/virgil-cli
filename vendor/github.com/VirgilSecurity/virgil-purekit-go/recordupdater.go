package purekit

import (
	"github.com/VirgilSecurity/virgil-phe-go"
	"github.com/pkg/errors"
)

type RecordUpdater struct {
	version uint32
	token   []byte
}

//NewRecordUpdater creates a new instance of RecordUpdater
func NewRecordUpdater(updateToken string) (*RecordUpdater, error) {
	tokenVersion, token, err := ParseVersionAndContent("UT", updateToken)
	if err != nil {
		return nil, errors.Wrap(err, "invalid update token")
	}
	return &RecordUpdater{
		version: tokenVersion,
		token:   token,
	}, nil
}

// UpdateRecord applies update token to a record to get updated record. It returns nil record if versions match
func (r *RecordUpdater) UpdateRecord(oldRecord []byte) (updatedRecord []byte, err error) {
	recordVersion, record, err := UnmarshalRecord(oldRecord)
	if err != nil {
		return nil, errors.Wrap(err, "invalid record")
	}

	if (recordVersion + 1) == r.version {
		newRec, err := phe.UpdateRecord(record, r.token)
		if err != nil {
			return nil, err
		}
		return MarshalRecord(r.version, newRec)
	}

	if recordVersion == r.version {
		return nil, nil
	}
	return nil, errors.Errorf("Record and update token versions mismatch: %d and %d", recordVersion, r.version)
}
