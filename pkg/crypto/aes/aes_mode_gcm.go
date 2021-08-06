package aes

import (
	"crypto/aes"
	"crypto/cipher"
)

type CryptoGCM struct {
	block cipher.Block
	key   []byte
}

func newAESCryptoGCM(key []byte) (Crypto, error) {
	b, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	r := &CryptoGCM{
		block: b,
		key:   key,
	}

	return r, nil
}


func (a *CryptoGCM) EncryptWithIV(plainText []byte, iv []byte) []byte {
	crypto, err := cipher.NewGCMWithNonceSize(a.block, len(iv))
	if err != nil {
		panic(err.Error())
	}

	cipherText := crypto.Seal(nil, iv, plainText, nil)
	return cipherText
}

func (a *CryptoGCM) DecryptWithIV(cipherText []byte, iv []byte) []byte {
	crypto, err := cipher.NewGCMWithNonceSize(a.block, len(iv))
	if err != nil {
		panic(err.Error())
	}
	plainText, err := crypto.Open(nil, iv, cipherText, nil)
	if err != nil {
		panic(err.Error())
	}
	return plainText
}
