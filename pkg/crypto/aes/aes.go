package aes

import (
	"errors"
)

// Crypto 定义 Crypto 接口
type Crypto interface {
	EncryptWithIV(plainText []byte, iv []byte) []byte
	DecryptWithIV(cipherText []byte, iv []byte) []byte
}

// 工作模式
type OperationMode string

const (
	CBC OperationMode = "CBC"
	CFB OperationMode = "CFB"
	OFB OperationMode = "OFB"
	CTR OperationMode = "CTR"
	GCM OperationMode = "GCM"
)

// New 实例化一个client
func New(operationMode OperationMode, key []byte) (Crypto, error) {
	switch operationMode {
	case CBC:
		return newAESCryptoCBC(key)
	case CFB:
		return newAESCryptoCFB(key)
	case OFB:
		return newAESCryptoOFB(key)
	case CTR:
		return newAESCryptoCTR(key)
	case GCM:
		return newAESCryptoGCM(key)
	}
	return nil, errors.New("Unknown Operation Mode ")
}
