package raf

import (
	"errors"
	"os"
)

// Algorithm selects the AEGIS variant used for encryption.
type Algorithm int

const (
	AEGIS128L  Algorithm = iota // 16-byte key, 16-byte nonce
	AEGIS128X2                  // 16-byte key, 16-byte nonce, 2-way parallel
	AEGIS128X4                  // 16-byte key, 16-byte nonce, 4-way parallel
	AEGIS256                    // 32-byte key, 32-byte nonce
	AEGIS256X2                  // 32-byte key, 32-byte nonce, 2-way parallel
	AEGIS256X4                  // 32-byte key, 32-byte nonce, 4-way parallel
)

// KeySize returns the key size in bytes for this algorithm.
func (a Algorithm) KeySize() int {
	switch a {
	case AEGIS128L, AEGIS128X2, AEGIS128X4:
		return 16
	case AEGIS256, AEGIS256X2, AEGIS256X4:
		return 32
	default:
		return 0
	}
}

func (a Algorithm) String() string {
	switch a {
	case AEGIS128L:
		return "AEGIS-128L"
	case AEGIS128X2:
		return "AEGIS-128X2"
	case AEGIS128X4:
		return "AEGIS-128X4"
	case AEGIS256:
		return "AEGIS-256"
	case AEGIS256X2:
		return "AEGIS-256X2"
	case AEGIS256X4:
		return "AEGIS-256X4"
	default:
		return "unknown"
	}
}

const (
	MinChunkSize = 1024      // Minimum plaintext chunk size in bytes
	MaxChunkSize = 1 << 20   // Maximum plaintext chunk size (1 MiB)
	HeaderSize   = 64        // On-disk file header size in bytes
	DefaultChunk = 64 * 1024 // Default chunk size (64 KiB)
)

// FileInfo contains metadata about an encrypted file.
type FileInfo struct {
	Size      int64     // Logical plaintext file size
	ChunkSize int       // Plaintext bytes per chunk
	Algorithm Algorithm // AEGIS variant
}

// Options configures file creation or opening.
type Options struct {
	// Algorithm selects the AEGIS variant. Required for Create.
	// Ignored for Open (read from the file header).
	Algorithm Algorithm

	// ChunkSize is the plaintext bytes per chunk. Must be a multiple of 16,
	// between MinChunkSize and MaxChunkSize. Zero means DefaultChunk (64 KiB).
	// Ignored for Open (read from the file header).
	ChunkSize int

	// Truncate, when set with Create, overwrites an existing file instead
	// of returning ErrExists.
	Truncate bool
}

// Store is the backing storage for an encrypted file.
// Since File is not safe for concurrent use, Store methods will not be
// called concurrently by a single File. Implementations do not need
// internal synchronization for use with a single File.
type Store interface {
	// ReadAt reads exactly len(p) bytes at offset off from the backing store.
	ReadAt(p []byte, off int64) (n int, err error)

	// WriteAt writes exactly len(p) bytes at offset off to the backing store.
	WriteAt(p []byte, off int64) (n int, err error)

	// GetSize returns the current size of the backing store in bytes.
	GetSize() (int64, error)

	// SetSize resizes the backing store (truncate or extend).
	SetSize(size int64) error

	// Sync flushes writes to durable storage.
	// Implementations that don't need durability may return nil.
	Sync() error
}

// NewFileStore wraps an *os.File as a Store.
func NewFileStore(f *os.File) Store {
	return &fileStore{f: f}
}

type fileStore struct {
	f *os.File
}

func (s *fileStore) ReadAt(p []byte, off int64) (int, error) {
	return s.f.ReadAt(p, off)
}

func (s *fileStore) WriteAt(p []byte, off int64) (int, error) {
	return s.f.WriteAt(p, off)
}

func (s *fileStore) GetSize() (int64, error) {
	fi, err := s.f.Stat()
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

func (s *fileStore) SetSize(size int64) error {
	return s.f.Truncate(size)
}

func (s *fileStore) Sync() error {
	return s.f.Sync()
}

var (
	// ErrAuth is returned when authentication fails (wrong key or tampered data).
	// Wrong key and tampered header are intentionally indistinguishable.
	ErrAuth = errors.New("raf: authentication failed")

	// ErrInvalidHeader is returned when the header has structural problems
	// (bad magic, unsupported version, invalid chunk size, algorithm mismatch).
	ErrInvalidHeader = errors.New("raf: invalid file header")

	// ErrBadChunkSize is returned when the chunk size is out of range or not
	// a multiple of 16.
	ErrBadChunkSize = errors.New("raf: invalid chunk size")

	// ErrBadKeyLength is returned when the key length doesn't match the algorithm.
	ErrBadKeyLength = errors.New("raf: invalid key length")

	// ErrExists is returned by Create when the store already contains a file
	// (backing size >= HeaderSize) and Truncate was not set.
	ErrExists = errors.New("raf: file already exists")

	// ErrClosed is returned when operating on a closed File.
	ErrClosed = errors.New("raf: file is closed")

	// ErrOverflow is returned when a write would exceed capacity limits.
	ErrOverflow = errors.New("raf: overflow")

	// ErrNegativeOffset is returned when a negative offset or size is passed.
	ErrNegativeOffset = errors.New("raf: negative offset or size")
)

// cAlgID maps Algorithm to the C AEGIS_RAF_ALG_* constant.
func cAlgID(a Algorithm) int {
	switch a {
	case AEGIS128L:
		return 1
	case AEGIS128X2:
		return 2
	case AEGIS128X4:
		return 3
	case AEGIS256:
		return 4
	case AEGIS256X2:
		return 5
	case AEGIS256X4:
		return 6
	default:
		return 0
	}
}

// algFromCID maps a C algorithm ID back to Algorithm.
func algFromCID(id int) Algorithm {
	switch id {
	case 1:
		return AEGIS128L
	case 2:
		return AEGIS128X2
	case 3:
		return AEGIS128X4
	case 4:
		return AEGIS256
	case 5:
		return AEGIS256X2
	case 6:
		return AEGIS256X4
	default:
		return Algorithm(-1)
	}
}
