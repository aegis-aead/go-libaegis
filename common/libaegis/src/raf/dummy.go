//go:build dummy

// Package raf exists only so that "go mod vendor" copies the C sources in
// this directory when this module is vendored (see the import chain rooted
// at common/libaegis/dummy.go). The "dummy" build tag is never satisfied,
// so this package is never compiled.
package raf
