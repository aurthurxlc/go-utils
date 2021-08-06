package aes

import (
	cr "crypto/rand"
	"math/rand"
	"strings"
	"time"
)

const mixedCharsetWithSymbol = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/~!@#$%^&*()_="
const mixedCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const letterCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const hexCharset = "0123456789abcdef"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func __randStringBytesMask(n int, charset string) string {
	src := rand.NewSource(time.Now().UnixNano())
	sb := strings.Builder{}
	sb.Grow(n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(charset) {
			sb.WriteByte(charset[idx])
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return sb.String()
}

func __randStringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.New(rand.NewSource(time.Now().UnixNano())).Intn(len(charset))]
	}
	return string(b)
}

// RandomString :
func RandomString(length int) string {
	return __randStringBytesMask(length, letterCharset)
}

// RandomString :
func RandomStringWithMix(length int) string {
	return __randStringBytesMask(length, mixedCharset)
}

// RandomStringWithSymbol :
func RandomStringWithSymbol(length int) string {
	return __randStringBytesMask(length, mixedCharsetWithSymbol)
}

// RandomStringWithHex :
func RandomStringWithHex(length int) string {
	return __randStringBytesMask(length, hexCharset)
}

// RandomString :
func RandomStringWithCharset(length int, charset string) string {
	return __randStringBytesMask(length, charset)
}

var alphaNum = []byte(`0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`)

// RandomCreateBytes generate random []byte by specify chars.
func RandomBytes(n int, alphabets ...byte) []byte {
	if len(alphabets) == 0 {
		alphabets = alphaNum
	}
	var bytes = make([]byte, n)
	var randBy bool
	if num, err := cr.Read(bytes); num != n || err != nil {
		rand.Seed(time.Now().UnixNano())
		randBy = true
	}
	for i, b := range bytes {
		if randBy {
			bytes[i] = alphabets[rand.Intn(len(alphabets))]
		} else {
			bytes[i] = alphabets[b%byte(len(alphabets))]
		}
	}
	return bytes
}