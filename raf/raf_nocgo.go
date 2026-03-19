//go:build !cgo || !go1.19
// +build !cgo !go1.19

package raf

import "github.com/aegis-aead/go-libaegis/common"

// File is an encrypted random-access file.
// This is the non-CGO stub; all operations panic.
type File struct{}

func Create(store Store, key []byte, opts *Options) (*File, error) {
	common.NotAvailable()
	return nil, nil
}

func Open(store Store, key []byte, opts *Options) (*File, error) {
	common.NotAvailable()
	return nil, nil
}

func Probe(store Store) (*FileInfo, error) {
	common.NotAvailable()
	return nil, nil
}

func (f *File) ReadAt(p []byte, off int64) (int, error) {
	common.NotAvailable()
	return 0, nil
}

func (f *File) WriteAt(p []byte, off int64) (int, error) {
	common.NotAvailable()
	return 0, nil
}

func (f *File) Truncate(size int64) error {
	common.NotAvailable()
	return nil
}

func (f *File) Size() (int64, error) {
	common.NotAvailable()
	return 0, nil
}

func (f *File) Sync() error {
	common.NotAvailable()
	return nil
}

func (f *File) Close() error {
	common.NotAvailable()
	return nil
}

func (f *File) Info() FileInfo {
	common.NotAvailable()
	return FileInfo{}
}
