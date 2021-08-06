package aes

type KeySize int

const (
	KeySize128 KeySize = 16
	KeySize192 KeySize = 24
	KeySize256 KeySize = 32
)

func GenerateKey(size KeySize) string {
	switch size {
	case KeySize128:
		return RandomStringWithSymbol(16)
	case KeySize192:
		return RandomStringWithSymbol(24)
	case KeySize256:
		return RandomStringWithSymbol(32)
	}

	return RandomStringWithSymbol(16)
}

func GenerateIV() string {
	return RandomStringWithSymbol(16)
}
