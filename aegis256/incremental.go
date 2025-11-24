//go:build cgo && go1.19
// +build cgo,go1.19

package aegis256

// #include <aegis.h>
// #cgo CFLAGS: -I../common/libaegis/src/include
import "C"

import (
	"github.com/aegis-aead/go-libaegis/common"
)

// Encrypter provides incremental authenticated encryption using AEGIS-256.
// Create one using NewEncrypter, call Encrypt or EncryptTo for each chunk
// of plaintext, then call Final to get the authentication tag.
type Encrypter struct {
	state     C.aegis256_state
	tagLen    int
	finalized bool
}

// NewEncrypter creates a new incremental encrypter.
// The key must be KeySize (32) bytes.
// The nonce must be at most NonceSize (32) bytes; shorter nonces are padded with zeros.
// The additionalData is authenticated but not encrypted.
// The tagLen must be 16 or 32.
func NewEncrypter(key, nonce, additionalData []byte, tagLen int) (*Encrypter, error) {
	if len(key) != KeySize {
		return nil, common.ErrBadKeyLength
	}
	if len(nonce) > NonceSize {
		return nil, common.ErrBadNonceLength
	}
	if tagLen != 16 && tagLen != 32 {
		return nil, common.ErrBadTagLength
	}

	// Pad nonce if needed
	if len(nonce) < NonceSize {
		nonce = append(nonce, make([]byte, NonceSize-len(nonce))...)
	}

	e := &Encrypter{tagLen: tagLen}
	C.aegis256_state_init(
		&e.state,
		slicePointerOrNull(additionalData),
		C.size_t(len(additionalData)),
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(&key[0]),
	)
	return e, nil
}

// Encrypt encrypts plaintext and returns ciphertext of the same length.
// Can be called multiple times for streaming encryption.
// Panics if called after Final.
func (e *Encrypter) Encrypt(plaintext []byte) []byte {
	if e.finalized {
		panic("aegis: Encrypt called after Final")
	}
	if len(plaintext) == 0 {
		return nil
	}
	ciphertext := make([]byte, len(plaintext))
	C.aegis256_state_encrypt_update(
		&e.state,
		(*C.uchar)(&ciphertext[0]),
		(*C.uchar)(&plaintext[0]),
		C.size_t(len(plaintext)),
	)
	return ciphertext
}

// EncryptTo encrypts plaintext and writes ciphertext to dst.
// The dst slice must have capacity for at least len(plaintext) bytes.
// Returns the ciphertext slice (a subslice of dst).
// If dst is nil or has insufficient capacity, a new slice is allocated.
// Panics if called after Final.
func (e *Encrypter) EncryptTo(dst, plaintext []byte) []byte {
	if e.finalized {
		panic("aegis: EncryptTo called after Final")
	}
	if len(plaintext) == 0 {
		return dst[:0]
	}
	if cap(dst) < len(plaintext) {
		dst = make([]byte, len(plaintext))
	} else {
		dst = dst[:len(plaintext)]
	}
	C.aegis256_state_encrypt_update(
		&e.state,
		(*C.uchar)(&dst[0]),
		(*C.uchar)(&plaintext[0]),
		C.size_t(len(plaintext)),
	)
	return dst
}

// Final finalizes the encryption and returns the authentication tag.
// The tag length was specified when creating the Encrypter.
// The Encrypter must not be used after calling Final.
func (e *Encrypter) Final() []byte {
	if e.finalized {
		panic("aegis: Final called twice")
	}
	e.finalized = true
	tag := make([]byte, e.tagLen)
	C.aegis256_state_encrypt_final(&e.state, (*C.uchar)(&tag[0]), C.size_t(e.tagLen))
	return tag
}

// Decrypter provides incremental authenticated decryption using AEGIS-256.
// Create one using NewDecrypter, call Decrypt or DecryptTo for each chunk
// of ciphertext, then call Final to verify the authentication tag.
//
// IMPORTANT: The decrypted plaintext MUST NOT be used or revealed until
// Final returns nil. If Final returns an error, all decrypted data must
// be discarded as it may have been tampered with.
type Decrypter struct {
	state     C.aegis256_state
	tagLen    int
	finalized bool
}

// NewDecrypter creates a new incremental decrypter.
// The key must be KeySize (32) bytes.
// The nonce must be at most NonceSize (32) bytes; shorter nonces are padded with zeros.
// The additionalData must match what was used during encryption.
// The tagLen must match what was used during encryption (16 or 32).
func NewDecrypter(key, nonce, additionalData []byte, tagLen int) (*Decrypter, error) {
	if len(key) != KeySize {
		return nil, common.ErrBadKeyLength
	}
	if len(nonce) > NonceSize {
		return nil, common.ErrBadNonceLength
	}
	if tagLen != 16 && tagLen != 32 {
		return nil, common.ErrBadTagLength
	}

	// Pad nonce if needed
	if len(nonce) < NonceSize {
		nonce = append(nonce, make([]byte, NonceSize-len(nonce))...)
	}

	d := &Decrypter{tagLen: tagLen}
	C.aegis256_state_init(
		&d.state,
		slicePointerOrNull(additionalData),
		C.size_t(len(additionalData)),
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(&key[0]),
	)
	return d, nil
}

// Decrypt decrypts ciphertext and returns plaintext of the same length.
// Can be called multiple times for streaming decryption.
//
// WARNING: The returned plaintext MUST NOT be used until Final returns nil.
// If Final returns an error, all decrypted data must be discarded.
//
// Panics if called after Final.
func (d *Decrypter) Decrypt(ciphertext []byte) []byte {
	if d.finalized {
		panic("aegis: Decrypt called after Final")
	}
	if len(ciphertext) == 0 {
		return nil
	}
	plaintext := make([]byte, len(ciphertext))
	C.aegis256_state_decrypt_update(
		&d.state,
		(*C.uchar)(&plaintext[0]),
		(*C.uchar)(&ciphertext[0]),
		C.size_t(len(ciphertext)),
	)
	return plaintext
}

// DecryptTo decrypts ciphertext and writes plaintext to dst.
// The dst slice must have capacity for at least len(ciphertext) bytes.
// Returns the plaintext slice (a subslice of dst).
// If dst is nil or has insufficient capacity, a new slice is allocated.
//
// WARNING: The plaintext MUST NOT be used until Final returns nil.
// If Final returns an error, all decrypted data must be discarded.
//
// Panics if called after Final.
func (d *Decrypter) DecryptTo(dst, ciphertext []byte) []byte {
	if d.finalized {
		panic("aegis: DecryptTo called after Final")
	}
	if len(ciphertext) == 0 {
		return dst[:0]
	}
	if cap(dst) < len(ciphertext) {
		dst = make([]byte, len(ciphertext))
	} else {
		dst = dst[:len(ciphertext)]
	}
	C.aegis256_state_decrypt_update(
		&d.state,
		(*C.uchar)(&dst[0]),
		(*C.uchar)(&ciphertext[0]),
		C.size_t(len(ciphertext)),
	)
	return dst
}

// Final verifies the authentication tag.
// The tag must be tagLen bytes (as specified when creating the Decrypter).
// Returns nil if the tag is valid, or ErrAuth if verification fails.
//
// If this returns an error, all previously decrypted data MUST be discarded
// as it may have been tampered with.
//
// The Decrypter must not be used after calling Final.
func (d *Decrypter) Final(tag []byte) error {
	if d.finalized {
		panic("aegis: Final called twice")
	}
	d.finalized = true
	if len(tag) != d.tagLen {
		return common.ErrBadTagLength
	}
	res := C.aegis256_state_decrypt_final(&d.state, (*C.uchar)(&tag[0]), C.size_t(d.tagLen))
	if res != 0 {
		return common.ErrAuth
	}
	return nil
}
