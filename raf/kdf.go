//go:build cgo && go1.19
// +build cgo,go1.19

package raf

/*
#include <aegis.h>
#include <stdint.h>

#cgo CFLAGS: -I../common/libaegis/src/include
*/
import "C"

// DeriveMasterKey derives a RAF master key from an application master key and
// a context string. The derived key has the same length as masterKey and can
// be passed to Create or Open.
//
// Deriving with different contexts from the same master key yields unrelated
// RAF keys, so separate files or families of files can be isolated without
// managing separate master keys. An empty context still derives a RAF-scoped
// key rather than passing the master key through unchanged.
//
// masterKey must be 16 or 32 bytes, and context must be no longer than
// MaxContextLen(len(masterKey)).
func DeriveMasterKey(masterKey []byte, context string) ([]byte, error) {
	if len(masterKey) != 16 && len(masterKey) != 32 {
		return nil, ErrBadKeyLength
	}
	if len(context) > MaxContextLen(len(masterKey)) {
		return nil, ErrContextTooLong
	}

	out := make([]byte, len(masterKey))

	// Go 1.19 has no unsafe.StringData, and the copy is negligible for a
	// one-shot key derivation.
	ctx := []byte(context)
	var ctxPtr *C.uint8_t
	if len(ctx) > 0 {
		ctxPtr = (*C.uint8_t)(&ctx[0])
	}

	if C.aegis_raf_derive_master_key(
		(*C.uint8_t)(&out[0]), C.size_t(len(out)),
		(*C.uint8_t)(&masterKey[0]), C.size_t(len(masterKey)),
		ctxPtr, C.size_t(len(ctx))) != 0 {
		return nil, ErrBadKeyLength
	}

	return out, nil
}
