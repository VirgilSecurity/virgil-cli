package models

import "time"

type DcmCertificateCreateRequest struct {
	Name             string `json:"name"`
	EncryptPublicKey string `json:"encrypt_public_key"`
	VerifyPublicKey  string `json:"verify_public_key"`
}

type DcmCertificateCreateResponse struct {
	Name           string `json:"name"`
	Certificate    string `json:"certificate"`
	EcaAddress     string `json:"eca_address"`
	EcaCertificate string `json:"eca_certificate"`
	RaAddress      string `json:"ra_address"`
	Lccf           string `json:"lccf"`
}

type DcmCertificateListItem struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type Device struct {
	ID        string    `json:"id"`
	DcmID     string    `json:"dcm_id"`
	ValidFrom time.Time `json:"valid_from"`
	ValidTo   time.Time `json:"valid_to"`
}
