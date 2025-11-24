//go:build !cgo || !go1.19
// +build !cgo !go1.19

package aegis128x2

import "github.com/aegis-aead/go-libaegis/common"

// Encrypter provides incremental authenticated encryption using AEGIS-128X2.
// This is a stub for when CGO is not available.
type Encrypter struct{}

// NewEncrypter creates a new incremental encrypter.
// Panics when CGO is not available.
func NewEncrypter(key, nonce, additionalData []byte, tagLen int) (*Encrypter, error) {
	common.NotAvailable()
	return nil, nil
}

// Encrypt is not available without CGO.
func (e *Encrypter) Encrypt(plaintext []byte) []byte {
	common.NotAvailable()
	return nil
}

// EncryptTo is not available without CGO.
func (e *Encrypter) EncryptTo(dst, plaintext []byte) []byte {
	common.NotAvailable()
	return nil
}

// Final is not available without CGO.
func (e *Encrypter) Final() []byte {
	common.NotAvailable()
	return nil
}

// Decrypter provides incremental authenticated decryption using AEGIS-128X2.
// This is a stub for when CGO is not available.
type Decrypter struct{}

// NewDecrypter creates a new incremental decrypter.
// Panics when CGO is not available.
func NewDecrypter(key, nonce, additionalData []byte, tagLen int) (*Decrypter, error) {
	common.NotAvailable()
	return nil, nil
}

// Decrypt is not available without CGO.
func (d *Decrypter) Decrypt(ciphertext []byte) []byte {
	common.NotAvailable()
	return nil
}

// DecryptTo is not available without CGO.
func (d *Decrypter) DecryptTo(dst, ciphertext []byte) []byte {
	common.NotAvailable()
	return nil
}

// Final is not available without CGO.
func (d *Decrypter) Final(tag []byte) error {
	common.NotAvailable()
	return nil
}
