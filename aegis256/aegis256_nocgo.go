//go:build !cgo || !go1.19
// +build !cgo !go1.19

package aegis256

import (
	"crypto/cipher"

	"github.com/aegis-aead/go-libaegis/common"
)

const (
	KeySize   = 32
	NonceSize = 32
)

type Aegis256 struct {
	common.Aegis
}

func New(key []byte, tagLen int) (cipher.AEAD, error) {
	common.NotAvailable()
	return nil, nil
}
