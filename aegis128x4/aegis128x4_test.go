package aegis128x4

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/aegis-aead/go-libaegis/common"
)

func mustPanic(t *testing.T, f func()) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("The code did not panic")
		}
	}()

	f()
}

func TestInexactOverlap(t *testing.T) {
	if !common.Available {
		t.Skip("cgo is required to use AEGIS")
	}

	textLength := 82
	key := make([]byte, KeySize)
	rand.Read(key)

	aead, err := New(key, 16)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)

	t.Run("Seal", func(t *testing.T) {
		originalCleartext := make([]byte, textLength)
		rand.Read(originalCleartext)

		buf := make([]byte, textLength*2+aead.Overhead())

		t.Run("Exact overlap", func(t *testing.T) {
			cleartext := buf[:textLength]
			copy(cleartext, originalCleartext)
			dst := buf[:0]
			aead.Seal(dst, nonce, cleartext, nil)
		})

		t.Run("One-byte-shift", func(t *testing.T) {
			cleartext := buf[:textLength]
			copy(cleartext, originalCleartext)
			dst := buf[1:1]
			mustPanic(t, func() { aead.Seal(dst, nonce, cleartext, nil) })
		})

		t.Run("One-byte-overlap", func(t *testing.T) {
			cleartext := buf[:textLength]
			copy(cleartext, originalCleartext)
			dst := buf[textLength-1 : textLength-1]
			mustPanic(t, func() { aead.Seal(dst, nonce, cleartext, nil) })
		})
	})

	t.Run("Open", func(t *testing.T) {
		cleartext := make([]byte, textLength)
		rand.Read(cleartext)

		control := aead.Seal(nil, nonce, cleartext, nil)
		buf := make([]byte, textLength+len(control))

		t.Run("Exact overlap", func(t *testing.T) {
			ciphertext := buf[:len(control)]
			copy(ciphertext, control)
			dst := buf[:0]
			aead.Open(dst, nonce, ciphertext, nil)
		})

		t.Run("One-byte-shift", func(t *testing.T) {
			ciphertext := buf[:len(control)]
			copy(ciphertext, control)
			dst := buf[1:1]
			mustPanic(t, func() { aead.Open(dst, nonce, ciphertext, nil) })
		})

		t.Run("One-byte-overlap", func(t *testing.T) {
			ciphertext := buf[:len(control)]
			copy(ciphertext, control)
			dst := buf[textLength-1 : textLength-1]
			mustPanic(t, func() { aead.Open(dst, nonce, ciphertext, nil) })
		})
	})
}

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
