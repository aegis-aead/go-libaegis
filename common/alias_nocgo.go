//go:build !cgo || !go1.19
// +build !cgo !go1.19

package common

// AnyOverlap reports whether x and y share memory at any (possibly overlapping) index.
// The memory beyond the slice length is ignored.
func AnyOverlap(x, y []byte) bool {
	// When CGO is not available, we can't provide meaningful overlap detection
	// but we also won't be doing any actual encryption operations
	return false
}

// InexactOverlap reports whether x and y share memory at any non-corresponding
// index. The memory beyond the slice length is ignored. Note that x and y can
// have different lengths and still not have any inexact overlap.
//
// InexactOverlap can be used to implement the requirements of the crypto/cipher
// AEAD, Block, BlockMode and Stream interfaces.
func InexactOverlap(x, y []byte) bool {
	// When CGO is not available, we can't provide meaningful overlap detection
	// but we also won't be doing any actual encryption operations
	return false
}
