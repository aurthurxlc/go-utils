package aes

import "bytes"

type PaddingMode string

const (
	Pkcs5Padding PaddingMode = "PKCS5_PADDING"
	Pkcs7Padding PaddingMode = "PKCS7_PADDING"
)

func __pkcsUnPadding(text []byte) []byte {
	n := len(text)
	if n == 0 {
		return text
	}
	paddingSize := int(text[n-1])
	return text[:n-paddingSize]
}

func __pkcs7Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

func __pkcs5Padding(cipherText []byte) []byte {
	return __pkcs7Padding(cipherText, 8)
}
