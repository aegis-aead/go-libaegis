package raf

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aegis-aead/go-libaegis/common"
)

// memStore is an in-memory Store for testing.
type memStore struct {
	data []byte
}

func newMemStore() *memStore {
	return &memStore{}
}

func (s *memStore) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(s.data)) {
		return 0, io.EOF
	}
	n := copy(p, s.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (s *memStore) WriteAt(p []byte, off int64) (int, error) {
	end := int(off) + len(p)
	if end > len(s.data) {
		grown := make([]byte, end)
		copy(grown, s.data)
		s.data = grown
	}
	copy(s.data[off:], p)
	return len(p), nil
}

func (s *memStore) GetSize() (int64, error) {
	return int64(len(s.data)), nil
}

func (s *memStore) SetSize(size int64) error {
	if int64(len(s.data)) == size {
		return nil
	}
	if size < int64(len(s.data)) {
		s.data = s.data[:size]
	} else {
		grown := make([]byte, size)
		copy(grown, s.data)
		s.data = grown
	}
	return nil
}

func (s *memStore) Sync() error {
	return nil
}

func TestCreateOpenRoundTrip(t *testing.T) {
	if !common.Available {
		t.Skip("CGO not available")
	}

	algorithms := []struct {
		alg     Algorithm
		keySize int
	}{
		{AEGIS128L, 16},
		{AEGIS128X2, 16},
		{AEGIS128X4, 16},
		{AEGIS256, 32},
		{AEGIS256X2, 32},
		{AEGIS256X4, 32},
	}

	for _, tc := range algorithms {
		t.Run(tc.alg.String(), func(t *testing.T) {
			store := newMemStore()
			key := make([]byte, tc.keySize)
			rand.Read(key)

			// Create
			f, err := Create(store, key, &Options{
				Algorithm: tc.alg,
				ChunkSize: MinChunkSize,
			})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}

			// Write
			data := []byte("hello, world! this is a test of RAF encryption.")
			n, err := f.WriteAt(data, 0)
			if err != nil {
				t.Fatalf("WriteAt: %v", err)
			}
			if n != len(data) {
				t.Fatalf("WriteAt: wrote %d, want %d", n, len(data))
			}

			// Read back
			buf := make([]byte, len(data))
			n, err = f.ReadAt(buf, 0)
			if err != nil {
				t.Fatalf("ReadAt: %v", err)
			}
			if !bytes.Equal(buf, data) {
				t.Fatalf("ReadAt: got %q, want %q", buf, data)
			}

			// Size
			size, err := f.Size()
			if err != nil {
				t.Fatalf("Size: %v", err)
			}
			if size != int64(len(data)) {
				t.Fatalf("Size: got %d, want %d", size, len(data))
			}

			// Close
			if err := f.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			// Reopen
			f2, err := Open(store, key, nil)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer f2.Close()

			// Read back after reopen
			buf2 := make([]byte, len(data))
			n, err = f2.ReadAt(buf2, 0)
			if err != nil {
				t.Fatalf("ReadAt after reopen: %v", err)
			}
			if !bytes.Equal(buf2, data) {
				t.Fatalf("ReadAt after reopen: got %q, want %q", buf2, data)
			}
		})
	}
}

func TestProbe(t *testing.T) {
	if !common.Available {
		t.Skip("CGO not available")
	}

	store := newMemStore()
	key := make([]byte, 32)
	rand.Read(key)

	f, err := Create(store, key, &Options{
		Algorithm: AEGIS256,
		ChunkSize: 4096,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err = f.WriteAt([]byte("probe test"), 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if err = f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	info, err := Probe(store)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if info.Algorithm != AEGIS256 {
		t.Fatalf("Probe algorithm: got %v, want AEGIS256", info.Algorithm)
	}
	if info.ChunkSize != 4096 {
		t.Fatalf("Probe chunk size: got %d, want 4096", info.ChunkSize)
	}
	if info.Size != 10 {
		t.Fatalf("Probe size: got %d, want 10", info.Size)
	}
}

func TestWrongKey(t *testing.T) {
	if !common.Available {
		t.Skip("CGO not available")
	}

	store := newMemStore()
	key := make([]byte, 32)
	rand.Read(key)

	f, err := Create(store, key, &Options{
		Algorithm: AEGIS256,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err = f.WriteAt([]byte("secret"), 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if err = f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)

	_, err = Open(store, wrongKey, nil)
	if err != ErrAuth {
		t.Fatalf("Open with wrong key: got %v, want ErrAuth", err)
	}
}

func TestCreateExists(t *testing.T) {
	if !common.Available {
		t.Skip("CGO not available")
	}

	store := newMemStore()
	key := make([]byte, 16)
	rand.Read(key)

	f, err := Create(store, key, &Options{Algorithm: AEGIS128L})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	f.Close()

	// Create again without Truncate should fail
	_, err = Create(store, key, &Options{Algorithm: AEGIS128L})
	if err != ErrExists {
		t.Fatalf("Create on existing: got %v, want ErrExists", err)
	}

	// Create with Truncate should succeed
	f2, err := Create(store, key, &Options{Algorithm: AEGIS128L, Truncate: true})
	if err != nil {
		t.Fatalf("Create with Truncate: %v", err)
	}
	f2.Close()
}

func TestTruncate(t *testing.T) {
	if !common.Available {
		t.Skip("CGO not available")
	}

	store := newMemStore()
	key := make([]byte, 16)
	rand.Read(key)

	f, err := Create(store, key, &Options{
		Algorithm: AEGIS128L,
		ChunkSize: MinChunkSize,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer f.Close()

	data := make([]byte, 5000)
	rand.Read(data)
	if _, err = f.WriteAt(data, 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}

	// Truncate to smaller
	if err := f.Truncate(100); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	size, _ := f.Size()
	if size != 100 {
		t.Fatalf("Size after truncate: got %d, want 100", size)
	}

	// Read back truncated data
	buf := make([]byte, 100)
	if _, err = f.ReadAt(buf, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(buf, data[:100]) {
		t.Fatal("Data mismatch after truncate")
	}
}

func TestRandomAccessWrite(t *testing.T) {
	if !common.Available {
		t.Skip("CGO not available")
	}

	store := newMemStore()
	key := make([]byte, 32)
	rand.Read(key)

	f, err := Create(store, key, &Options{
		Algorithm: AEGIS256,
		ChunkSize: MinChunkSize,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer f.Close()

	// Write at offset 0
	if _, err = f.WriteAt([]byte("AAAA"), 0); err != nil {
		t.Fatalf("WriteAt(0): %v", err)
	}
	// Write at offset 1000 (creates gap)
	if _, err = f.WriteAt([]byte("BBBB"), 1000); err != nil {
		t.Fatalf("WriteAt(1000): %v", err)
	}

	size, _ := f.Size()
	if size != 1004 {
		t.Fatalf("Size: got %d, want 1004", size)
	}

	// Read back
	buf := make([]byte, 4)
	if _, err = f.ReadAt(buf, 0); err != nil {
		t.Fatalf("ReadAt(0): %v", err)
	}
	if string(buf) != "AAAA" {
		t.Fatalf("Read at 0: got %q", buf)
	}

	if _, err = f.ReadAt(buf, 1000); err != nil {
		t.Fatalf("ReadAt(1000): %v", err)
	}
	if string(buf) != "BBBB" {
		t.Fatalf("Read at 1000: got %q", buf)
	}

	// Gap should be zero-filled
	gap := make([]byte, 10)
	if _, err = f.ReadAt(gap, 4); err != nil {
		t.Fatalf("ReadAt(4): %v", err)
	}
	for i, b := range gap {
		if b != 0 {
			t.Fatalf("Gap byte %d: got %d, want 0", i, b)
		}
	}
}

func TestFileStore(t *testing.T) {
	if !common.Available {
		t.Skip("CGO not available")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "test.raf")

	key := make([]byte, 16)
	rand.Read(key)

	// Create with FileStore
	osf, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	store := NewFileStore(osf)

	f, err := Create(store, key, &Options{
		Algorithm: AEGIS128L,
		ChunkSize: MinChunkSize,
	})
	if err != nil {
		osf.Close()
		t.Fatalf("Create: %v", err)
	}

	data := []byte("file store test data with some content to verify")
	if _, err = f.WriteAt(data, 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if err = f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	osf.Close()

	// Reopen with FileStore
	osf2, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer osf2.Close()
	store2 := NewFileStore(osf2)

	f2, err := Open(store2, key, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f2.Close()

	buf := make([]byte, len(data))
	if _, err = f2.ReadAt(buf, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(buf, data) {
		t.Fatalf("Data mismatch: got %q, want %q", buf, data)
	}
}

func TestLargeWrite(t *testing.T) {
	if !common.Available {
		t.Skip("CGO not available")
	}

	store := newMemStore()
	key := make([]byte, 16)
	rand.Read(key)

	f, err := Create(store, key, &Options{
		Algorithm: AEGIS128L,
		ChunkSize: MinChunkSize,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer f.Close()

	// Write data spanning multiple chunks
	data := make([]byte, MinChunkSize*3+500)
	rand.Read(data)

	n, err := f.WriteAt(data, 0)
	if err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if n != len(data) {
		t.Fatalf("WriteAt: wrote %d, want %d", n, len(data))
	}

	// Read back
	buf := make([]byte, len(data))
	n, err = f.ReadAt(buf, 0)
	if err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(buf, data) {
		t.Fatal("Data mismatch on large write")
	}
}

func TestCloseReopen(t *testing.T) {
	if !common.Available {
		t.Skip("CGO not available")
	}

	store := newMemStore()
	key := make([]byte, 32)
	rand.Read(key)

	// Multiple close/reopen cycles
	for i := 0; i < 5; i++ {
		var f *File
		var err error
		if i == 0 {
			f, err = Create(store, key, &Options{
				Algorithm: AEGIS256,
				ChunkSize: MinChunkSize,
			})
		} else {
			f, err = Open(store, key, nil)
		}
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}

		data := []byte(fmt.Sprintf("iteration %d", i))
		if _, werr := f.WriteAt(data, 0); werr != nil {
			t.Fatalf("iteration %d WriteAt: %v", i, werr)
		}
		if cerr := f.Close(); cerr != nil {
			t.Fatalf("iteration %d Close: %v", i, cerr)
		}
	}

	// Final read
	f, err := Open(store, key, nil)
	if err != nil {
		t.Fatalf("final Open: %v", err)
	}
	defer f.Close()

	buf := make([]byte, 20)
	n, _ := f.ReadAt(buf, 0)
	got := string(buf[:n])
	if got != "iteration 4" {
		t.Fatalf("final read: got %q, want %q", got, "iteration 4")
	}
}

func TestClosedFileErrors(t *testing.T) {
	if !common.Available {
		t.Skip("CGO not available")
	}

	store := newMemStore()
	key := make([]byte, 16)
	rand.Read(key)

	f, err := Create(store, key, &Options{Algorithm: AEGIS128L})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	f.Close()

	if _, err := f.ReadAt(make([]byte, 10), 0); err != ErrClosed {
		t.Fatalf("ReadAt on closed: got %v, want ErrClosed", err)
	}
	if _, err := f.WriteAt(make([]byte, 10), 0); err != ErrClosed {
		t.Fatalf("WriteAt on closed: got %v, want ErrClosed", err)
	}
	if err := f.Truncate(0); err != ErrClosed {
		t.Fatalf("Truncate on closed: got %v, want ErrClosed", err)
	}
	if _, err := f.Size(); err != ErrClosed {
		t.Fatalf("Size on closed: got %v, want ErrClosed", err)
	}
	if err := f.Sync(); err != ErrClosed {
		t.Fatalf("Sync on closed: got %v, want ErrClosed", err)
	}
	if err := f.Close(); err != ErrClosed {
		t.Fatalf("Double close: got %v, want ErrClosed", err)
	}
}

func TestBadKeyLength(t *testing.T) {
	if !common.Available {
		t.Skip("CGO not available")
	}

	store := newMemStore()

	_, err := Create(store, []byte("short"), &Options{Algorithm: AEGIS256})
	if err != ErrBadKeyLength {
		t.Fatalf("Create with short key: got %v, want ErrBadKeyLength", err)
	}
}

func TestBadChunkSize(t *testing.T) {
	if !common.Available {
		t.Skip("CGO not available")
	}

	store := newMemStore()
	key := make([]byte, 16)
	rand.Read(key)

	// Too small
	_, err := Create(store, key, &Options{Algorithm: AEGIS128L, ChunkSize: 512})
	if err != ErrBadChunkSize {
		t.Fatalf("Create with small chunk: got %v, want ErrBadChunkSize", err)
	}

	// Not multiple of 16
	_, err = Create(store, key, &Options{Algorithm: AEGIS128L, ChunkSize: 1025})
	if err != ErrBadChunkSize {
		t.Fatalf("Create with unaligned chunk: got %v, want ErrBadChunkSize", err)
	}
}

func TestInfo(t *testing.T) {
	if !common.Available {
		t.Skip("CGO not available")
	}

	store := newMemStore()
	key := make([]byte, 32)
	rand.Read(key)

	f, err := Create(store, key, &Options{
		Algorithm: AEGIS256X2,
		ChunkSize: 8192,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer f.Close()

	if _, err = f.WriteAt([]byte("info test"), 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}

	info := f.Info()
	if info.Algorithm != AEGIS256X2 {
		t.Fatalf("Info algorithm: got %v, want AEGIS256X2", info.Algorithm)
	}
	if info.ChunkSize != 8192 {
		t.Fatalf("Info chunk size: got %d, want 8192", info.ChunkSize)
	}
	if info.Size != 9 {
		t.Fatalf("Info size: got %d, want 9", info.Size)
	}
}

// failSyncStore wraps a memStore but makes Sync() fail.
type failSyncStore struct {
	*memStore
}

func (s *failSyncStore) Sync() error {
	return errors.New("sync boom")
}

// countSyncStore counts Sync calls.
type countSyncStore struct {
	*memStore
	syncCount int
}

func (s *countSyncStore) Sync() error {
	s.syncCount++
	return nil
}

func TestCallbackErrorPropagation(t *testing.T) {
	if !common.Available {
		t.Skip("CGO not available")
	}

	// Create a valid file first with a working store.
	goodStore := newMemStore()
	key := make([]byte, 16)
	rand.Read(key)

	f, err := Create(goodStore, key, &Options{
		Algorithm: AEGIS128L,
		ChunkSize: MinChunkSize,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err = f.WriteAt([]byte("test"), 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if err = f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Try to open with a store whose ReadAt fails.
	badStore := &failReadStore{data: goodStore.data}
	_, err = Open(badStore, key, nil)
	if err == nil {
		t.Fatal("Open with failing ReadAt should error")
	}
	if !strings.Contains(err.Error(), "read boom") {
		t.Fatalf("Open error should contain underlying cause, got: %v", err)
	}
}

// failReadStore wraps memStore but makes ReadAt fail after first call.
type failReadStore struct {
	data  []byte
	calls int
}

func (s *failReadStore) ReadAt(p []byte, off int64) (int, error) {
	s.calls++
	// Allow the first read (probe header), fail on second (open header verify)
	if s.calls > 1 {
		return 0, errors.New("read boom")
	}
	if off >= int64(len(s.data)) {
		return 0, io.EOF
	}
	n := copy(p, s.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (s *failReadStore) WriteAt(p []byte, off int64) (int, error) {
	return 0, errors.New("write boom")
}

func (s *failReadStore) GetSize() (int64, error) {
	return int64(len(s.data)), nil
}

func (s *failReadStore) SetSize(size int64) error {
	return nil
}

func (s *failReadStore) Sync() error {
	return nil
}

func TestCloseSyncError(t *testing.T) {
	if !common.Available {
		t.Skip("CGO not available")
	}

	underlying := newMemStore()
	key := make([]byte, 16)
	rand.Read(key)

	// Create with working store.
	f, err := Create(underlying, key, &Options{
		Algorithm: AEGIS128L,
		ChunkSize: MinChunkSize,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	f.WriteAt([]byte("data"), 0)
	f.Close()

	// Reopen with a store whose Sync fails.
	store := &failSyncStore{memStore: underlying}
	f2, err := Open(store, key, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	err = f2.Close()
	if err == nil {
		t.Fatal("Close should return sync error")
	}
	if !strings.Contains(err.Error(), "sync boom") {
		t.Fatalf("Close error should contain underlying cause, got: %v", err)
	}
}

func TestNegativeOffset(t *testing.T) {
	if !common.Available {
		t.Skip("CGO not available")
	}

	store := newMemStore()
	key := make([]byte, 16)
	rand.Read(key)

	f, err := Create(store, key, &Options{Algorithm: AEGIS128L})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer f.Close()

	if _, err := f.ReadAt(make([]byte, 10), -1); err != ErrNegativeOffset {
		t.Fatalf("ReadAt(-1): got %v, want ErrNegativeOffset", err)
	}
	if _, err := f.WriteAt([]byte("x"), -1); err != ErrNegativeOffset {
		t.Fatalf("WriteAt(-1): got %v, want ErrNegativeOffset", err)
	}
	if err := f.Truncate(-1); err != ErrNegativeOffset {
		t.Fatalf("Truncate(-1): got %v, want ErrNegativeOffset", err)
	}
}

func TestCloseSingleSync(t *testing.T) {
	if !common.Available {
		t.Skip("CGO not available")
	}

	underlying := newMemStore()
	key := make([]byte, 16)
	rand.Read(key)

	f, err := Create(underlying, key, &Options{
		Algorithm: AEGIS128L,
		ChunkSize: MinChunkSize,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	f.WriteAt([]byte("data"), 0)
	f.Close()

	// Reopen with a counting store.
	store := &countSyncStore{memStore: underlying}
	f2, err := Open(store, key, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	store.syncCount = 0
	err = f2.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	if store.syncCount != 1 {
		t.Fatalf("Close called Sync %d times, want exactly 1", store.syncCount)
	}
}

func TestSyncError(t *testing.T) {
	if !common.Available {
		t.Skip("CGO not available")
	}

	store := &failSyncStore{memStore: newMemStore()}
	key := make([]byte, 16)
	rand.Read(key)

	f, err := Create(store, key, &Options{
		Algorithm: AEGIS128L,
		ChunkSize: MinChunkSize,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	err = f.Sync()
	if err == nil {
		t.Fatal("Sync should fail")
	}
	if !strings.Contains(err.Error(), "sync boom") {
		t.Fatalf("Sync error should contain underlying cause, got: %v", err)
	}
	f.Close()
}
