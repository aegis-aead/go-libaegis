//go:build dummy

// Package libaegis exists only so that "go mod vendor" copies the embedded C
// source tree when a Go module depends on these bindings.
//
// "go mod vendor" only copies build-relevant files (.c, .h, .s, ...) from
// directories that are Go packages reachable in the import graph, so every
// directory containing C sources carries a dummy.go and is blank-imported
// below. "go mod vendor" resolves imports ignoring build constraints, so the
// never-satisfied "dummy" build tag keeps these packages out of real builds
// (loose .c files in a non-cgo package would otherwise fail to compile)
// while still making the directories visible to vendoring.
//
// The chain is rooted by a blank import of this package in
// common/vendor_dirs.go, so consumers of the bindings vendor the C tree
// automatically.
package libaegis

import (
	_ "github.com/aegis-aead/go-libaegis/common/libaegis/src/aegis128l"
	_ "github.com/aegis-aead/go-libaegis/common/libaegis/src/aegis128x2"
	_ "github.com/aegis-aead/go-libaegis/common/libaegis/src/aegis128x4"
	_ "github.com/aegis-aead/go-libaegis/common/libaegis/src/aegis256"
	_ "github.com/aegis-aead/go-libaegis/common/libaegis/src/aegis256x2"
	_ "github.com/aegis-aead/go-libaegis/common/libaegis/src/aegis256x4"
	_ "github.com/aegis-aead/go-libaegis/common/libaegis/src/common"
	_ "github.com/aegis-aead/go-libaegis/common/libaegis/src/include"
	_ "github.com/aegis-aead/go-libaegis/common/libaegis/src/raf"
)
