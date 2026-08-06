//go:build dummy

package common

// Roots the vendoring chain: consumers that vendor these bindings also get
// the embedded C source tree. See common/libaegis/dummy.go for the mechanism.
import _ "github.com/aegis-aead/go-libaegis/common/libaegis"
