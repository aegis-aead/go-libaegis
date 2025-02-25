package common

import (
	"crypto/cipher"
	"crypto/subtle"
	"fmt"
)

// #include <aegis.h>
// #cgo CFLAGS: -Ilibaegis/src/include -I. -O3
import "C"

type Aegis struct {
	Key    []byte
	TagLen int
	cipher.AEAD
}

// The overhead of the AEAD, in bytes, corresponding to the length of the tag.
func (aead *Aegis) Overhead() int {
	return aead.TagLen
}

// Wipe clears the key from memory (best-effort)
func (aead *Aegis) Wipe() {
	subtle.XORBytes(aead.Key, aead.Key, aead.Key)
	aead.TagLen = 0
}

var (
	ErrAuth           = fmt.Errorf("message authentication failed")
	ErrTruncated      = fmt.Errorf("ciphertext too short")
	ErrBadNonceLength = fmt.Errorf("invalid nonce length")
	ErrBadKeyLength   = fmt.Errorf("invalid key length")
	ErrBadTagLength   = fmt.Errorf("invalid tag length")
)

func init() {
	C.aegis_init()
}
