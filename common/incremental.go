//go:build cgo && go1.19
// +build cgo,go1.19

package common

// #include <aegis.h>
// #cgo CFLAGS: -Ilibaegis/src/include -I. -O3
import "C"

import "fmt"

// ErrFinalized is returned when an incremental operation is used after finalization.
var ErrFinalized = fmt.Errorf("operation already finalized")
