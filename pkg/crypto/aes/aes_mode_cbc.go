package aes

import (
	"crypto/aes"
	"crypto/cipher"
)

type CryptoCBC struct {
	block       cipher.Block
	key         []byte
	paddingMode PaddingMode
}

func newAESCryptoCBC(key []byte) (Crypto, error) {
	b, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	r := &CryptoCBC{
		block:       b,
		key:         key,
		paddingMode: Pkcs7Padding,
	}

	return r, nil
}

func (a *CryptoCBC) EncryptWithIV(plainText []byte, iv []byte) []byte {
	switch a.paddingMode {
	case Pkcs5Padding:
		plainText = __pkcs5Padding(plainText)
	case Pkcs7Padding:
		plainText = __pkcs7Padding(plainText, a.block.BlockSize())
	}

	cipherText := make([]byte, len(plainText))
	crypto := cipher.NewCBCEncrypter(a.block, iv)
	crypto.CryptBlocks(cipherText, plainText)

	return cipherText
}

func (a *CryptoCBC) DecryptWithIV(cipherText []byte, iv []byte) []byte {
	plainText := make([]byte, len(cipherText))
	crypto := cipher.NewCBCDecrypter(a.block, iv)
	crypto.CryptBlocks(plainText, cipherText)
	plainText = __pkcsUnPadding(plainText)

	return plainText
}
