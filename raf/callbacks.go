//go:build cgo && go1.19
// +build cgo,go1.19

package raf

// #include <aegis.h>
// #include <stdint.h>
// #cgo CFLAGS: -I../common/libaegis/src/include
import "C"

import (
	"crypto/rand"
	"runtime/cgo"
	"unsafe"
)

// callbackState is what the cgo.Handle wraps. It holds the Store and
// a place to stash the most recent callback error so the Go caller
// can surface it instead of a generic errno.
type callbackState struct {
	store        Store
	lastErr      error
	syncDisabled bool // set before raf_close to prevent double-sync
}

//export goRAFReadAt
func goRAFReadAt(handle C.uintptr_t, buf *C.uint8_t, length C.size_t, off C.uint64_t) C.int {
	state := cgo.Handle(handle).Value().(*callbackState)
	gobuf := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(length))
	_, err := state.store.ReadAt(gobuf, int64(off))
	if err != nil {
		state.lastErr = err
		return -1
	}
	return 0
}

//export goRAFWriteAt
func goRAFWriteAt(handle C.uintptr_t, buf *C.uint8_t, length C.size_t, off C.uint64_t) C.int {
	state := cgo.Handle(handle).Value().(*callbackState)
	gobuf := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(length))
	_, err := state.store.WriteAt(gobuf, int64(off))
	if err != nil {
		state.lastErr = err
		return -1
	}
	return 0
}

//export goRAFGetSize
func goRAFGetSize(handle C.uintptr_t, size *C.uint64_t) C.int {
	state := cgo.Handle(handle).Value().(*callbackState)
	sz, err := state.store.GetSize()
	if err != nil {
		state.lastErr = err
		return -1
	}
	*size = C.uint64_t(sz)
	return 0
}

//export goRAFSetSize
func goRAFSetSize(handle C.uintptr_t, size C.uint64_t) C.int {
	state := cgo.Handle(handle).Value().(*callbackState)
	err := state.store.SetSize(int64(size))
	if err != nil {
		state.lastErr = err
		return -1
	}
	return 0
}

//export goRAFSync
func goRAFSync(handle C.uintptr_t) C.int {
	state := cgo.Handle(handle).Value().(*callbackState)
	if state.syncDisabled {
		return 0
	}
	err := state.store.Sync()
	if err != nil {
		state.lastErr = err
		return -1
	}
	return 0
}

//export goRAFRandom
func goRAFRandom(out *C.uint8_t, length C.size_t) C.int {
	buf := unsafe.Slice((*byte)(unsafe.Pointer(out)), int(length))
	_, err := rand.Read(buf)
	if err != nil {
		return -1
	}
	return 0
}
