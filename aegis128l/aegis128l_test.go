package aegis128l

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/aegis-aead/go-libaegis/common"
)

func Example() {
	if !common.Available {
		return
	}
	key := make([]byte, KeySize)
	rand.Read(key)
	aead, err := New(key, 16)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)

	ciphertext := aead.Seal(nil, nonce, []byte("hello, world!"), nil)

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(plaintext))
	// Output: hello, world!
}

func TestBufferOverlapPanic(t *testing.T) {
	if !common.Available {
		t.Skip("AEGIS-128L not available")
	}

	key := make([]byte, KeySize)
	rand.Read(key)
	aead, err := New(key, 16)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)

	t.Run("Seal dst/cleartext inexact overlap", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for dst/cleartext inexact overlap")
			} else if panicMsg, ok := r.(string); !ok || panicMsg != "aegis: invalid buffer overlap of output and plaintext" {
				t.Errorf("Unexpected panic message: %v", r)
			}
		}()

		// Create overlapping buffers
		buffer := make([]byte, 100)
		dst := buffer[0:50]
		cleartext := buffer[10:30] // Overlaps with dst

		aead.Seal(dst, nonce, cleartext, nil)
	})

	t.Run("Seal dst/additionalData inexact overlap", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for dst/additionalData inexact overlap")
			} else if panicMsg, ok := r.(string); !ok || panicMsg != "aegis: invalid buffer overlap of output and additional data" {
				t.Errorf("Unexpected panic message: %v", r)
			}
		}()

		// Create overlapping buffers
		buffer := make([]byte, 100)
		dst := buffer[0:50]
		cleartext := []byte("hello")
		additionalData := buffer[20:40] // Overlaps with dst

		aead.Seal(dst, nonce, cleartext, additionalData)
	})

	t.Run("Open plaintext/ciphertext inexact overlap", func(t *testing.T) {
		// First create valid ciphertext
		validCiphertext := aead.Seal(nil, nonce, []byte("test message"), nil)

		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for plaintext/ciphertext inexact overlap")
			} else if panicMsg, ok := r.(string); !ok || panicMsg != "aegis: invalid buffer overlap of output and ciphertext" {
				t.Errorf("Unexpected panic message: %v", r)
			}
		}()

		// Create overlapping buffers
		buffer := make([]byte, 100)
		copy(buffer[20:], validCiphertext) // Copy ciphertext into buffer
		plaintext := buffer[0:30]          // Overlaps with ciphertext
		ciphertext := buffer[20 : 20+len(validCiphertext)]

		aead.Open(plaintext, nonce, ciphertext, nil)
	})

	t.Run("Open plaintext/additionalData inexact overlap", func(t *testing.T) {
		// First create valid ciphertext
		validCiphertext := aead.Seal(nil, nonce, []byte("test message"), nil)

		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for plaintext/additionalData inexact overlap")
			} else if panicMsg, ok := r.(string); !ok || panicMsg != "aegis: invalid buffer overlap of output and additional data" {
				t.Errorf("Unexpected panic message: %v", r)
			}
		}()

		// Create overlapping buffers
		buffer := make([]byte, 100)
		plaintext := buffer[0:30]
		additionalData := buffer[15:35] // Overlaps with plaintext

		aead.Open(plaintext, nonce, validCiphertext, additionalData)
	})

	t.Run("Valid exact overlap cases should not panic", func(t *testing.T) {
		// Test that exact overlaps (same starting address) don't panic
		buffer := make([]byte, 100)

		// Seal with dst and cleartext pointing to the same location (valid)
		dst := buffer[50:80]
		cleartext := buffer[50:70] // Same start, different length - this is allowed

		// This should not panic
		result := aead.Seal(dst, nonce, cleartext, nil)
		if len(result) == 0 {
			t.Error("Expected successful encryption with exact overlap")
		}
	})

	t.Run("Non-overlapping buffers should not panic", func(t *testing.T) {
		// Test that non-overlapping buffers work fine

		// Use completely separate buffers to avoid any possible overlap
		cleartext := []byte("hello world")
		additionalData := []byte("additional data")

		// Seal with separate buffers - should not panic
		result := aead.Seal(nil, nonce, cleartext, additionalData)
		if len(result) == 0 {
			t.Error("Expected successful encryption with non-overlapping buffers")
		}

		// Decrypt with separate buffers too - should not panic
		decrypted, err := aead.Open(nil, nonce, result, additionalData)
		if err != nil {
			t.Errorf("Decryption failed: %v", err)
		}
		if len(decrypted) == 0 {
			t.Error("Expected successful decryption with non-overlapping buffers")
		}
	})
}
