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

	// Check for buffer overlap per cipher.AEAD requirements
	if common.InexactOverlap(dst, cleartext) {
		panic("aegis: invalid buffer overlap of output and plaintext")
	}
	if common.InexactOverlap(dst, additionalData) {
		panic("aegis: invalid buffer overlap of output and additional data")
	}

	outLen := len(cleartext) + aead.TagLen
	ret, out := common.GrowSlice(dst, outLen)
	res := C.aegis128x4_encrypt((*C.uchar)(&out[0]), C.size_t(aead.TagLen), slicePointerOrNull(cleartext),
		C.size_t(len(cleartext)), slicePointerOrNull(additionalData), C.size_t(len(additionalData)), (*C.uchar)(&nonce[0]), (*C.uchar)(&aead.Key[0]))
	if res != 0 {
		panic("encryption failed")
	}
	return ret
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

	// Check for buffer overlap per cipher.AEAD requirements
	if common.InexactOverlap(plaintext, ciphertext) {
		panic("aegis: invalid buffer overlap of output and ciphertext")
	}
	if common.InexactOverlap(plaintext, additionalData) {
		panic("aegis: invalid buffer overlap of output and additional data")
	}

	outLen := len(ciphertext) - aead.TagLen
	ret, out := common.GrowSlice(plaintext, outLen)
	res := C.aegis128x4_decrypt(slicePointerOrNull(out), (*C.uchar)(&ciphertext[0]),
		C.size_t(len(ciphertext)), C.size_t(aead.TagLen), slicePointerOrNull(additionalData), C.size_t(len(additionalData)), (*C.uchar)(&nonce[0]), (*C.uchar)(&aead.Key[0]))
	if res != 0 {
		return nil, common.ErrAuth
	}
	return ret, nil
}

func slicePointerOrNull(s []byte) (ptr *C.uchar) {
	if len(s) == 0 {
		return
	}
	return (*C.uchar)(&s[0])
}
