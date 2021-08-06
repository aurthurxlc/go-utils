package aes

import (
	"crypto/aes"
	"crypto/cipher"
)

type CryptoCTR struct {
	block cipher.Block
	key   []byte
}

func newAESCryptoCTR(key []byte) (Crypto, error) {
	b, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	r := &CryptoCTR{
		block: b,
		key:   key,
	}

	return r, nil
}

func (a *CryptoCTR) EncryptWithIV(plainText []byte, iv []byte) []byte {
	cipherText := make([]byte, len(plainText))
	crypto := cipher.NewCTR(a.block, iv)
	crypto.XORKeyStream(cipherText, plainText)
	return cipherText
}

func (a *CryptoCTR) DecryptWithIV(cipherText []byte, iv []byte) []byte {
	plainText := make([]byte, len(cipherText))
	crypto := cipher.NewCTR(a.block, iv)
	crypto.XORKeyStream(plainText, cipherText)

	return plainText
}
