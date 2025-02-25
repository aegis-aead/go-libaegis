//go:build !go1.20
// +build !go1.20

package common

// Wipe clears the key from memory (best-effort)
func (aead *Aegis) Wipe() {
	for i := range aead.Key {
		aead.Key[i] = 0
	}
	aead.TagLen = 0
}
