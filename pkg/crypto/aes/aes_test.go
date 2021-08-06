package aes

import (
	"encoding/base64"
	"fmt"
	"testing"
)

var key []byte
var iv []byte
var pText string

func init() {
	// 准备参数
	key = []byte(GenerateKey(KeySize256))
	iv =[]byte(GenerateIV())
	pText = RandomString(99)

	fmt.Println("key: " + string(key))
	fmt.Println("iv: " + string(iv))
	fmt.Println("pText: " + pText)
}

func Test_AESCBC(t *testing.T) {
	AESCrypto, err := New(CBC, key)
	if err != nil {
		t.Error(err)
		return
	}
	cText := AESCrypto.EncryptWithIV([]byte(pText),iv)
	fmt.Println("cText: " + base64.StdEncoding.EncodeToString(cText))

	dpText := AESCrypto.DecryptWithIV(cText,iv)
	fmt.Println("pText: " + string(dpText))
	if string(dpText) == pText {
		t.Log("success")
	}
}

func Test_AESCFB(t *testing.T) {
	AESCrypto, err := New(CFB, key)
	if err != nil {
		t.Error(err)
		return
	}
	cText := AESCrypto.EncryptWithIV([]byte(pText),iv)
	fmt.Println("cText: " + base64.StdEncoding.EncodeToString(cText))

	dpText := AESCrypto.DecryptWithIV(cText,iv)
	fmt.Println("pText: " + string(dpText))
	if string(dpText) == pText {
		t.Log("success")
	}
}

func Test_AESOFB(t *testing.T) {
	AESCrypto, err := New(OFB, key)
	if err != nil {
		t.Error(err)
		return
	}
	cText := AESCrypto.EncryptWithIV([]byte(pText),iv)
	fmt.Println("cText: " + base64.StdEncoding.EncodeToString(cText))

	dpText := AESCrypto.DecryptWithIV(cText,iv)
	fmt.Println("pText: " + string(dpText))
	if string(dpText) == pText {
		t.Log("success")
	}
}

func Test_AESCTR(t *testing.T) {
	AESCrypto, err := New(CTR, key)
	if err != nil {
		t.Error(err)
		return
	}
	cText := AESCrypto.EncryptWithIV([]byte(pText),iv)
	fmt.Println("cText: " + base64.StdEncoding.EncodeToString(cText))

	dpText := AESCrypto.DecryptWithIV(cText,iv)
	fmt.Println("pText: " + string(dpText))
	if string(dpText) == pText {
		t.Log("success")
	}
}

func Test_AESGCM(t *testing.T) {
	AESCrypto, err := New(GCM, key)
	if err != nil {
		t.Error(err)
		return
	}
	cText := AESCrypto.EncryptWithIV([]byte(pText),iv)

	fmt.Println("cText: " + base64.StdEncoding.EncodeToString(cText))

	dpText := AESCrypto.DecryptWithIV(cText,iv)
	fmt.Println("pText: " + string(dpText))
	if string(dpText) == pText {
		t.Log("success")
	}
}
