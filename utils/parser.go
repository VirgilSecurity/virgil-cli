package utils

import (
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// ParseVersionAndContent splits string into 3 parts: Prefix, version and decoded base64 content
func ParseVersionAndContent(prefix, str string) (version uint32, content []byte, err error) {
	parts := strings.Split(str, ".")
	if len(parts) != 3 || parts[0] != prefix {
		return 0, nil, errors.New("invalid string")
	}

	nVersion, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, nil, errors.Wrap(err, "invalid string")
	}

	if nVersion < 1 {
		return 0, nil, errors.Wrap(err, "invalid version")
	}
	version = uint32(nVersion)

	content, err = base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return 0, nil, errors.Wrap(err, "invalid string")
	}
	return
}

// ParseCombinedEntities splits string into 4 parts: Prefix, version and decoded base64 content Phe and Kms keys
func ParseCombinedEntities(prefix, combinedEntity string) (version uint32, pheKeyContent, kmsKeyContent []byte, err error) {
	parts := strings.Split(combinedEntity, ".")
	if len(parts) != 4 || parts[0] != prefix {
		return 0, nil, nil, errors.New("invalid string")
	}

	nVersion, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, nil, nil, errors.Wrap(err, "invalid string")
	}

	if nVersion < 1 {
		return 0, nil, nil, errors.Wrap(err, "invalid version")
	}
	version = uint32(nVersion)

	pheKeyContent, err = base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return 0, nil, nil, errors.Wrap(err, "invalid string")
	}

	kmsKeyContent, err = base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return 0, nil, nil, errors.Wrap(err, "invalid string")
	}
	return
}
