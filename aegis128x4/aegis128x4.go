//go:build cgo && go1.19
// +build cgo,go1.19

package aegis128x4

// #include <aegis.h>
// #cgo CFLAGS: -I../common/libaegis/src/include
import "C"

import (
	"crypto/cipher"

	"github.com/aegis-aead/go-libaegis/common"
)

const (
	KeySize   = 16
	NonceSize = 16
)

type Aegis128X4 struct {
	common.Aegis
}

// The nonce size, in bytes.
func (aead *Aegis128X4) NonceSize() int {
	return NonceSize
}

// New returns a new AEAD that uses the provided key and tag length.
// The key must be 16 bytes long.
// The tag length must be 16 or 32.
func New(key []byte, tagLen int) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, common.ErrBadKeyLength
	}
	if tagLen != 16 && tagLen != 32 {
		return nil, common.ErrBadTagLength
	}
	a := new(Aegis128X4)
	a.TagLen = tagLen
	a.Key = key
	return a, nil
}

func (aead *Aegis128X4) Seal(dst, nonce, cleartext, additionalData []byte) []byte {
	nonceLen := len(nonce)
	if nonceLen > aead.NonceSize() {
		panic("aegis: invalid nonce length")
	}
	if nonceLen < aead.NonceSize() {
		nonce = append(nonce, make([]byte, aead.NonceSize()-nonceLen)...)
	}
	outLen := len(cleartext) + aead.TagLen
	var buf []byte
	inplace := false
	if cap(dst)-len(dst) >= outLen {
		inplace = true
		buf = dst[len(dst) : len(dst)+outLen]
	} else {
		buf = make([]byte, outLen)
	}
	if common.InexactOverlap(buf, cleartext) {
		panic("aegis: invalid buffer overlap")
	}
	res := C.aegis128x4_encrypt((*C.uchar)(&buf[0]), C.size_t(aead.TagLen), slicePointerOrNull(cleartext),
		C.size_t(len(cleartext)), slicePointerOrNull(additionalData), C.size_t(len(additionalData)), (*C.uchar)(&nonce[0]), (*C.uchar)(&aead.Key[0]))
	if res != 0 {
		panic("encryption failed")
	}
	if inplace {
		return dst[:len(dst)+outLen]
	}
	return append(dst, buf...)
}

func (aead *Aegis128X4) Open(plaintext, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	nonceLen := len(nonce)
	if nonceLen > aead.NonceSize() {
		panic("aegis: invalid nonce length")
	}
	if nonceLen < aead.NonceSize() {
		nonce = append(nonce, make([]byte, aead.NonceSize()-nonceLen)...)
	}
	if len(ciphertext) < aead.TagLen {
		return nil, common.ErrTruncated
	}
	outLen := len(ciphertext) - aead.TagLen
	var buf []byte
	inplace := false
	if cap(plaintext)-len(plaintext) >= outLen {
		inplace = true
		buf = plaintext[len(plaintext) : len(plaintext)+outLen]
	} else {
		buf = make([]byte, len(ciphertext)-aead.TagLen)
	}
	if common.InexactOverlap(buf, ciphertext) {
		panic("aegis: invalid buffer overlap")
	}
	res := C.aegis128x4_decrypt(slicePointerOrNull(buf), (*C.uchar)(&ciphertext[0]),
		C.size_t(len(ciphertext)), C.size_t(aead.TagLen), slicePointerOrNull(additionalData), C.size_t(len(additionalData)), (*C.uchar)(&nonce[0]), (*C.uchar)(&aead.Key[0]))
	if res != 0 {
		return nil, common.ErrAuth
	}
	if inplace {
		return plaintext[:len(plaintext)+outLen], nil
	}
	return append(plaintext, buf...), nil
}

func slicePointerOrNull(s []byte) (ptr *C.uchar) {
	if len(s) == 0 {
		return
	}
	return (*C.uchar)(&s[0])
}
