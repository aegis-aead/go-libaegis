//go:build !cgo || !go1.19
// +build !cgo !go1.19

package aegis128x2

import (
	"crypto/cipher"

	"github.com/aegis-aead/go-libaegis/common"
)

const (
	KeySize   = 16
	NonceSize = 16
)

type Aegis128X2 struct {
	common.Aegis
}

func New(key []byte, tagLen int) (cipher.AEAD, error) {
	common.NotAvailable()
	return nil, nil
}
