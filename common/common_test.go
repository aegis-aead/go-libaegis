package common

import "testing"

func TestOverhead(t *testing.T) {
	aead := Aegis{TagLen: 16}
	if aead.Overhead() != aead.TagLen {
		panic("Unexpected overhead")
	}
}
