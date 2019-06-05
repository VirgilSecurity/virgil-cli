package virgil_crypto_go

type HashType int

var (
	SHA256 = HashType(VirgilHashAlgorithm_SHA256)
	SHA384 = HashType(VirgilHashAlgorithm_SHA384)
	SHA512 = HashType(VirgilHashAlgorithm_SHA512)

)
