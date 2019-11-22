package keygen

import (
	"gopkg.in/virgil.v5/cryptoimpl"
)

func generateKeypairEncoded() (sk []byte, pk []byte, err error) {
	keyPair, err := cryptoimpl.NewKeypair()
	if err != nil {
		return nil, nil, err
	}

	if sk, err = keyPair.PrivateKey().Encode(nil); err != nil {
		return nil, nil, err
	}

	if pk, err = keyPair.PublicKey().Encode(); err != nil {
		return nil, nil, err
	}
	return sk, pk, nil
}
