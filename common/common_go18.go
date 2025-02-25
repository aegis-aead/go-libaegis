//go:build cgo && !go1.19
// +build cgo,!go1.19

package common

// #cgo CFLAGS: -Ilibaegis/src/include
import "C"
