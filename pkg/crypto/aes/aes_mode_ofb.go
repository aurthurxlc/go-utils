package aes

import (
	"crypto/aes"
	"crypto/cipher"
)

type CryptoOFB struct {
	block cipher.Block
	key   []byte
}

func newAESCryptoOFB(key []byte) (Crypto, error) {
	b, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	r := &CryptoOFB{
		block: b,
		key:   key,
	}

	return r, nil
}

func (a *CryptoOFB) EncryptWithIV(plainText []byte, iv []byte) []byte {
	cipherText := make([]byte, len(plainText))
	crypto := cipher.NewOFB(a.block, iv)
	crypto.XORKeyStream(cipherText, plainText)
	return cipherText
}

func (a *CryptoOFB) DecryptWithIV(cipherText []byte, iv []byte) []byte {
	plainText := make([]byte, len(cipherText))
	crypto := cipher.NewOFB(a.block, iv)
	crypto.XORKeyStream(plainText, cipherText)
	return plainText
}
