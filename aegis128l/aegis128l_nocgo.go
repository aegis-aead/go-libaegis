//go:build !cgo
// +build !cgo

package aegis128l

import (
	"crypto/cipher"

	"github.com/aegis-aead/go-libaegis/common"
)

const (
	KeySize   = 16
	NonceSize = 16
)

type Aegis128L struct {
	common.Aegis
}

func New(key []byte, tagLen int) (cipher.AEAD, error) {
	common.NotAvailable()
	return nil, nil
}
