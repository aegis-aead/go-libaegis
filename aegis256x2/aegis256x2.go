//go:build cgo && go1.19
// +build cgo,go1.19

package aegis256x2

// #include <aegis.h>
// #cgo CFLAGS: -I../common/libaegis/src/include
import "C"

import (
	"crypto/cipher"

	"github.com/aegis-aead/go-libaegis/common"
)

const (
	KeySize   = 32
	NonceSize = 32
)

type Aegis256X2 struct {
	common.Aegis
}

// The nonce size, in bytes.
func (aead *Aegis256X2) NonceSize() int {
	return NonceSize
}

// New returns a new AEAD that uses the provided key and tag length.
// The key must be 32 bytes long.
// The tag length must be 16 or 32.
func New(key []byte, tagLen int) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, common.ErrBadKeyLength
	}
	if tagLen != 16 && tagLen != 32 {
		return nil, common.ErrBadTagLength
	}
	a := new(Aegis256X2)
	a.TagLen = tagLen
	a.Key = key
	return a, nil
}

func (aead *Aegis256X2) Seal(dst, nonce, cleartext, additionalData []byte) []byte {
	nonceLen := len(nonce)
	if nonceLen > aead.NonceSize() {
		panic("aegis: invalid nonce length")
	}
	if nonceLen < aead.NonceSize() {
		nonce = append(nonce, make([]byte, aead.NonceSize()-nonceLen)...)
	}
	outLen := len(cleartext) + aead.TagLen
	full, buf := sliceGrowOrNew(dst, outLen)
	res := C.aegis256x2_encrypt((*C.uchar)(&buf[0]), C.size_t(aead.TagLen), slicePointerOrNull(cleartext),
		C.size_t(len(cleartext)), slicePointerOrNull(additionalData), C.size_t(len(additionalData)), (*C.uchar)(&nonce[0]), (*C.uchar)(&aead.Key[0]))
	if res != 0 {
		panic("encryption failed")
	}
	return full
}

func (aead *Aegis256X2) Open(plaintext, nonce, ciphertext, additionalData []byte) ([]byte, error) {
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
	full, buf := sliceGrowOrNew(plaintext, outLen)
	res := C.aegis256x2_decrypt(slicePointerOrNull(buf), (*C.uchar)(&ciphertext[0]),
		C.size_t(len(ciphertext)), C.size_t(aead.TagLen), slicePointerOrNull(additionalData), C.size_t(len(additionalData)), (*C.uchar)(&nonce[0]), (*C.uchar)(&aead.Key[0]))
	if res != 0 {
		return nil, common.ErrAuth
	}
	return full, nil
}

func slicePointerOrNull(s []byte) (ptr *C.uchar) {
	if len(s) == 0 {
		return
	}
	return (*C.uchar)(&s[0])
}

func sliceGrowOrNew(s []byte, l int) (full, tail []byte) {
	if cap(s)-len(s) >= l {
		return s[:len(s)+l], s[len(s) : len(s)+l]
	} else {
		n := make([]byte, len(s)+l)
		copy(n, s)
		return n, n[len(s):]
	}
}
