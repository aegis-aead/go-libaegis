//go:build cgo
// +build cgo

package common

import (
	"crypto/cipher"
	"fmt"
)

// #include <aegis.h>
// #cgo CFLAGS: -Ilibaegis/src/include -I. -O3
import "C"

const (
	Available = true
)

type Aegis struct {
	Key    []byte
	TagLen int
	cipher.AEAD
}

// The overhead of the AEAD, in bytes, corresponding to the length of the tag.
func (aead *Aegis) Overhead() int {
	return aead.TagLen
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
