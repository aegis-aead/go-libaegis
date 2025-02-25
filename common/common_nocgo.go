//go:build !cgo
// +build !cgo

package common

import (
	"crypto/cipher"
	"fmt"
)

const (
	Available = false
)

type Aegis struct {
	cipher.AEAD
}

// The overhead of the AEAD, in bytes, corresponding to the length of the tag.
func (aead *Aegis) Overhead() int {
	NotAvailable()
	return 0
}

// Wipe clears the key from memory (best-effort)
func (aead *Aegis) Wipe() {
	NotAvailable()
}

func (aead *Aegis) NonceSize() int {
	NotAvailable()
	return 0
}

func New(key []byte, tagLen int) (cipher.AEAD, error) {
	NotAvailable()
	return nil, nil
}

func (aead *Aegis) Seal(dst, nonce, cleartext, additionalData []byte) []byte {
	NotAvailable()
	return nil
}

func (aead *Aegis) Open(plaintext, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	NotAvailable()
	return nil, nil
}

var (
	ErrAuth           = fmt.Errorf("message authentication failed")
	ErrTruncated      = fmt.Errorf("ciphertext too short")
	ErrBadNonceLength = fmt.Errorf("invalid nonce length")
	ErrBadKeyLength   = fmt.Errorf("invalid key length")
	ErrBadTagLength   = fmt.Errorf("invalid tag length")
)

func init() {
	NotAvailable()
}

func NotAvailable() {
	panic("cgo is required to use AEGIS")
}
