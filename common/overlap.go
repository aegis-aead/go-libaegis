package common

import "unsafe"

func InexactOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 {
		return false
	}
	if &x[0] == &y[0] {
		return false
	}
	x0 := uintptr(unsafe.Pointer(&x[0]))
	x1 := x0 + uintptr(len(x))
	y0 := uintptr(unsafe.Pointer(&y[0]))
	y1 := y0 + uintptr(len(y))
	return x0 < y1 && y0 < x1
}
