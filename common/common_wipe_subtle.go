//go:build go1.20
// +build go1.20

package common

import "crypto/subtle"

// Wipe clears the key from memory (best-effort)
func (aead *Aegis) Wipe() {
	subtle.XORBytes(aead.Key, aead.Key, aead.Key)
	aead.TagLen = 0
}
