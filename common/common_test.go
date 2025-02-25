package common

import "testing"

func TestOverhead(t *testing.T) {
	if !Available {
		return
	}
	aead := Aegis{TagLen: 16}
	if aead.Overhead() != aead.TagLen {
		panic("Unexpected overhead")
	}
	aead.Wipe()
}
