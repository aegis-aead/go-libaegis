//go:build cgo && go1.19
// +build cgo,go1.19

package raf

/*
#include <aegis.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#cgo CFLAGS: -I../common/libaegis/src/include

// Forward-declare Go-exported callbacks.
extern int goRAFReadAt(uintptr_t h, uint8_t *buf, size_t len, uint64_t off);
extern int goRAFWriteAt(uintptr_t h, const uint8_t *buf, size_t len, uint64_t off);
extern int goRAFGetSize(uintptr_t h, uint64_t *size);
extern int goRAFSetSize(uintptr_t h, uint64_t size);
extern int goRAFSync(uintptr_t h);
extern int goRAFRandom(uint8_t *out, size_t len);

// --- I/O callback shims ---
// These dereference the C-allocated box to recover the cgo.Handle.
// On failure they set errno = EIO as required by the C API (aegis_raf.h:112).

#ifndef EIO
#define EIO 5
#endif

static int shim_read_at(void *user, uint8_t *buf, size_t len, uint64_t off) {
	uintptr_t h = *(uintptr_t *)user;
	int ret = goRAFReadAt(h, buf, len, off);
	if (ret != 0) { errno = EIO; }
	return ret;
}

static int shim_write_at(void *user, const uint8_t *buf, size_t len, uint64_t off) {
	uintptr_t h = *(uintptr_t *)user;
	int ret = goRAFWriteAt(h, buf, len, off);
	if (ret != 0) { errno = EIO; }
	return ret;
}

static int shim_get_size(void *user, uint64_t *size) {
	uintptr_t h = *(uintptr_t *)user;
	int ret = goRAFGetSize(h, size);
	if (ret != 0) { errno = EIO; }
	return ret;
}

static int shim_set_size(void *user, uint64_t size) {
	uintptr_t h = *(uintptr_t *)user;
	int ret = goRAFSetSize(h, size);
	if (ret != 0) { errno = EIO; }
	return ret;
}

static int shim_sync(void *user) {
	uintptr_t h = *(uintptr_t *)user;
	int ret = goRAFSync(h);
	if (ret != 0) { errno = EIO; }
	return ret;
}

static int shim_random(void *user, uint8_t *out, size_t len) {
	(void)user;
	return goRAFRandom(out, len);
}

// --- Helpers ---

static aegis_raf_io make_raf_io(void *box) {
	aegis_raf_io io;
	io.user     = box;
	io.read_at  = shim_read_at;
	io.write_at = shim_write_at;
	io.get_size = shim_get_size;
	io.set_size = shim_set_size;
	io.sync     = shim_sync;
	return io;
}

static aegis_raf_rng make_raf_rng(void) {
	aegis_raf_rng rng;
	rng.user   = NULL;
	rng.random = shim_random;
	return rng;
}

// Portable aligned allocation.
static void *raf_aligned_alloc(size_t alignment, size_t size) {
#ifdef _WIN32
	return _aligned_malloc(size, alignment);
#else
	void *ptr = NULL;
	if (posix_memalign(&ptr, alignment, size) != 0) {
		return NULL;
	}
	return ptr;
#endif
}

static void raf_aligned_free(void *ptr) {
#ifdef _WIN32
	_aligned_free(ptr);
#else
	free(ptr);
#endif
}

// --- Variant dispatch ---
// Each function switches on the C algorithm ID to call the right variant.

static size_t raf_scratch_size(int alg, uint32_t chunk_size) {
	switch (alg) {
	case AEGIS_RAF_ALG_128L:  return aegis128l_raf_scratch_size(chunk_size);
	case AEGIS_RAF_ALG_128X2: return aegis128x2_raf_scratch_size(chunk_size);
	case AEGIS_RAF_ALG_128X4: return aegis128x4_raf_scratch_size(chunk_size);
	case AEGIS_RAF_ALG_256:   return aegis256_raf_scratch_size(chunk_size);
	case AEGIS_RAF_ALG_256X2: return aegis256x2_raf_scratch_size(chunk_size);
	case AEGIS_RAF_ALG_256X4: return aegis256x4_raf_scratch_size(chunk_size);
	default: return 0;
	}
}

static int raf_create(int alg, void *ctx, const aegis_raf_io *io,
	const aegis_raf_rng *rng, const aegis_raf_config *cfg, const uint8_t *key)
{
	switch (alg) {
	case AEGIS_RAF_ALG_128L:  return aegis128l_raf_create((aegis128l_raf_ctx *)ctx, io, rng, cfg, key);
	case AEGIS_RAF_ALG_128X2: return aegis128x2_raf_create((aegis128x2_raf_ctx *)ctx, io, rng, cfg, key);
	case AEGIS_RAF_ALG_128X4: return aegis128x4_raf_create((aegis128x4_raf_ctx *)ctx, io, rng, cfg, key);
	case AEGIS_RAF_ALG_256:   return aegis256_raf_create((aegis256_raf_ctx *)ctx, io, rng, cfg, key);
	case AEGIS_RAF_ALG_256X2: return aegis256x2_raf_create((aegis256x2_raf_ctx *)ctx, io, rng, cfg, key);
	case AEGIS_RAF_ALG_256X4: return aegis256x4_raf_create((aegis256x4_raf_ctx *)ctx, io, rng, cfg, key);
	default: errno = EINVAL; return -1;
	}
}

static int raf_open(int alg, void *ctx, const aegis_raf_io *io,
	const aegis_raf_rng *rng, const aegis_raf_config *cfg, const uint8_t *key)
{
	switch (alg) {
	case AEGIS_RAF_ALG_128L:  return aegis128l_raf_open((aegis128l_raf_ctx *)ctx, io, rng, cfg, key);
	case AEGIS_RAF_ALG_128X2: return aegis128x2_raf_open((aegis128x2_raf_ctx *)ctx, io, rng, cfg, key);
	case AEGIS_RAF_ALG_128X4: return aegis128x4_raf_open((aegis128x4_raf_ctx *)ctx, io, rng, cfg, key);
	case AEGIS_RAF_ALG_256:   return aegis256_raf_open((aegis256_raf_ctx *)ctx, io, rng, cfg, key);
	case AEGIS_RAF_ALG_256X2: return aegis256x2_raf_open((aegis256x2_raf_ctx *)ctx, io, rng, cfg, key);
	case AEGIS_RAF_ALG_256X4: return aegis256x4_raf_open((aegis256x4_raf_ctx *)ctx, io, rng, cfg, key);
	default: errno = EINVAL; return -1;
	}
}

static int raf_read(int alg, void *ctx, uint8_t *out, size_t *bytes_read,
	size_t len, uint64_t offset)
{
	switch (alg) {
	case AEGIS_RAF_ALG_128L:  return aegis128l_raf_read((aegis128l_raf_ctx *)ctx, out, bytes_read, len, offset);
	case AEGIS_RAF_ALG_128X2: return aegis128x2_raf_read((aegis128x2_raf_ctx *)ctx, out, bytes_read, len, offset);
	case AEGIS_RAF_ALG_128X4: return aegis128x4_raf_read((aegis128x4_raf_ctx *)ctx, out, bytes_read, len, offset);
	case AEGIS_RAF_ALG_256:   return aegis256_raf_read((aegis256_raf_ctx *)ctx, out, bytes_read, len, offset);
	case AEGIS_RAF_ALG_256X2: return aegis256x2_raf_read((aegis256x2_raf_ctx *)ctx, out, bytes_read, len, offset);
	case AEGIS_RAF_ALG_256X4: return aegis256x4_raf_read((aegis256x4_raf_ctx *)ctx, out, bytes_read, len, offset);
	default: errno = EINVAL; return -1;
	}
}

static int raf_write(int alg, void *ctx, size_t *bytes_written,
	const uint8_t *in, size_t len, uint64_t offset)
{
	switch (alg) {
	case AEGIS_RAF_ALG_128L:  return aegis128l_raf_write((aegis128l_raf_ctx *)ctx, bytes_written, in, len, offset);
	case AEGIS_RAF_ALG_128X2: return aegis128x2_raf_write((aegis128x2_raf_ctx *)ctx, bytes_written, in, len, offset);
	case AEGIS_RAF_ALG_128X4: return aegis128x4_raf_write((aegis128x4_raf_ctx *)ctx, bytes_written, in, len, offset);
	case AEGIS_RAF_ALG_256:   return aegis256_raf_write((aegis256_raf_ctx *)ctx, bytes_written, in, len, offset);
	case AEGIS_RAF_ALG_256X2: return aegis256x2_raf_write((aegis256x2_raf_ctx *)ctx, bytes_written, in, len, offset);
	case AEGIS_RAF_ALG_256X4: return aegis256x4_raf_write((aegis256x4_raf_ctx *)ctx, bytes_written, in, len, offset);
	default: errno = EINVAL; return -1;
	}
}

static int raf_truncate(int alg, void *ctx, uint64_t size) {
	switch (alg) {
	case AEGIS_RAF_ALG_128L:  return aegis128l_raf_truncate((aegis128l_raf_ctx *)ctx, size);
	case AEGIS_RAF_ALG_128X2: return aegis128x2_raf_truncate((aegis128x2_raf_ctx *)ctx, size);
	case AEGIS_RAF_ALG_128X4: return aegis128x4_raf_truncate((aegis128x4_raf_ctx *)ctx, size);
	case AEGIS_RAF_ALG_256:   return aegis256_raf_truncate((aegis256_raf_ctx *)ctx, size);
	case AEGIS_RAF_ALG_256X2: return aegis256x2_raf_truncate((aegis256x2_raf_ctx *)ctx, size);
	case AEGIS_RAF_ALG_256X4: return aegis256x4_raf_truncate((aegis256x4_raf_ctx *)ctx, size);
	default: errno = EINVAL; return -1;
	}
}

static int raf_get_size(int alg, const void *ctx, uint64_t *size) {
	switch (alg) {
	case AEGIS_RAF_ALG_128L:  return aegis128l_raf_get_size((const aegis128l_raf_ctx *)ctx, size);
	case AEGIS_RAF_ALG_128X2: return aegis128x2_raf_get_size((const aegis128x2_raf_ctx *)ctx, size);
	case AEGIS_RAF_ALG_128X4: return aegis128x4_raf_get_size((const aegis128x4_raf_ctx *)ctx, size);
	case AEGIS_RAF_ALG_256:   return aegis256_raf_get_size((const aegis256_raf_ctx *)ctx, size);
	case AEGIS_RAF_ALG_256X2: return aegis256x2_raf_get_size((const aegis256x2_raf_ctx *)ctx, size);
	case AEGIS_RAF_ALG_256X4: return aegis256x4_raf_get_size((const aegis256x4_raf_ctx *)ctx, size);
	default: errno = EINVAL; return -1;
	}
}

static int raf_sync(int alg, void *ctx) {
	switch (alg) {
	case AEGIS_RAF_ALG_128L:  return aegis128l_raf_sync((aegis128l_raf_ctx *)ctx);
	case AEGIS_RAF_ALG_128X2: return aegis128x2_raf_sync((aegis128x2_raf_ctx *)ctx);
	case AEGIS_RAF_ALG_128X4: return aegis128x4_raf_sync((aegis128x4_raf_ctx *)ctx);
	case AEGIS_RAF_ALG_256:   return aegis256_raf_sync((aegis256_raf_ctx *)ctx);
	case AEGIS_RAF_ALG_256X2: return aegis256x2_raf_sync((aegis256x2_raf_ctx *)ctx);
	case AEGIS_RAF_ALG_256X4: return aegis256x4_raf_sync((aegis256x4_raf_ctx *)ctx);
	default: errno = EINVAL; return -1;
	}
}

static void raf_close(int alg, void *ctx) {
	switch (alg) {
	case AEGIS_RAF_ALG_128L:  aegis128l_raf_close((aegis128l_raf_ctx *)ctx); break;
	case AEGIS_RAF_ALG_128X2: aegis128x2_raf_close((aegis128x2_raf_ctx *)ctx); break;
	case AEGIS_RAF_ALG_128X4: aegis128x4_raf_close((aegis128x4_raf_ctx *)ctx); break;
	case AEGIS_RAF_ALG_256:   aegis256_raf_close((aegis256_raf_ctx *)ctx); break;
	case AEGIS_RAF_ALG_256X2: aegis256x2_raf_close((aegis256x2_raf_ctx *)ctx); break;
	case AEGIS_RAF_ALG_256X4: aegis256x4_raf_close((aegis256x4_raf_ctx *)ctx); break;
	}
}

// --- High-level helpers that build all C structs internally ---
// These avoid passing Go stack pointers containing pointers into C.

static int raf_do_create(int alg, void *ctx, void *box,
	uint8_t *scratch_buf, size_t scratch_len,
	uint32_t chunk_size, uint8_t flags, const uint8_t *key)
{
	aegis_raf_io      io  = make_raf_io(box);
	aegis_raf_rng     rng = make_raf_rng();
	aegis_raf_scratch scr = { scratch_buf, scratch_len };
	aegis_raf_config  cfg = { &scr, NULL, chunk_size, flags };
	return raf_create(alg, ctx, &io, &rng, &cfg, key);
}

static int raf_do_open(int alg, void *ctx, void *box,
	uint8_t *scratch_buf, size_t scratch_len,
	uint32_t chunk_size, const uint8_t *key)
{
	aegis_raf_io      io  = make_raf_io(box);
	aegis_raf_rng     rng = make_raf_rng();
	aegis_raf_scratch scr = { scratch_buf, scratch_len };
	aegis_raf_config  cfg = { &scr, NULL, chunk_size, 0 };
	return raf_open(alg, ctx, &io, &rng, &cfg, key);
}

static int raf_do_probe(void *box, aegis_raf_info *info) {
	aegis_raf_io io = make_raf_io(box);
	return aegis_raf_probe(&io, info);
}
*/
import "C"

import (
	"fmt"
	"io"
	"runtime/cgo"
	"syscall"
	"unsafe"

	_ "github.com/aegis-aead/go-libaegis/common" // link libaegis C code
)

// File is an encrypted random-access file.
//
// A File is NOT safe for concurrent use from multiple goroutines.
// This is stricter than *os.File (which is concurrent-safe at the kernel level).
// If concurrent access is needed, callers must provide external synchronization.
type File struct {
	ctx        unsafe.Pointer // C-allocated context (64-byte aligned, 512 bytes)
	scratchBuf unsafe.Pointer // C-allocated scratch buffer
	handleBox  unsafe.Pointer // C-allocated uintptr_t box holding cgo.Handle
	cbState    *callbackState // stashes Store callback errors
	algID      C.int
	chunkSize  int
	closed     bool
}

// resources holds C-allocated resources for a File. Used during Create/Open
// to ensure cleanup on partial failure.
type resources struct {
	ctx     unsafe.Pointer
	scratch unsafe.Pointer
	box     unsafe.Pointer
	handle  cgo.Handle
	state   *callbackState
}

func (r *resources) free() {
	if r.handle != 0 {
		r.handle.Delete()
	}
	if r.box != nil {
		C.free(r.box)
	}
	if r.ctx != nil {
		C.raf_aligned_free(r.ctx)
	}
	if r.scratch != nil {
		C.raf_aligned_free(r.scratch)
	}
}

// allocResources allocates the C-side resources needed for Create/Open.
func allocResources(store Store, algID C.int, chunkSize int) (*resources, error) {
	r := &resources{}

	r.state = &callbackState{store: store}
	r.box = C.malloc(C.size_t(unsafe.Sizeof(C.uintptr_t(0))))
	if r.box == nil {
		return nil, fmt.Errorf("raf: failed to allocate handle box")
	}
	r.handle = cgo.NewHandle(r.state)
	*(*C.uintptr_t)(r.box) = C.uintptr_t(r.handle)

	r.ctx = C.raf_aligned_alloc(64, 512)
	if r.ctx == nil {
		r.free()
		return nil, fmt.Errorf("raf: failed to allocate context")
	}

	scratchSize := C.raf_scratch_size(algID, C.uint32_t(chunkSize))
	if scratchSize == 0 {
		r.free()
		return nil, fmt.Errorf("raf: failed to compute scratch size")
	}
	r.scratch = C.raf_aligned_alloc(C.AEGIS_RAF_SCRATCH_ALIGN, scratchSize)
	if r.scratch == nil {
		r.free()
		return nil, fmt.Errorf("raf: failed to allocate scratch buffer")
	}

	return r, nil
}

// Create creates a new encrypted file on the given store.
//
// Create considers the store to already contain a file when its size is
// at least HeaderSize (64) bytes. If so and Truncate is not set in opts,
// Create returns ErrExists. Stores smaller than HeaderSize are treated
// as empty regardless of their contents.
func Create(store Store, key []byte, opts *Options) (*File, error) {
	if opts == nil {
		return nil, fmt.Errorf("raf: options are required for Create")
	}

	alg := opts.Algorithm
	if len(key) != alg.KeySize() {
		return nil, ErrBadKeyLength
	}

	chunkSize := opts.ChunkSize
	if chunkSize == 0 {
		chunkSize = DefaultChunk
	}
	if chunkSize < MinChunkSize || chunkSize > MaxChunkSize || chunkSize%16 != 0 {
		return nil, ErrBadChunkSize
	}

	algID := C.int(cAlgID(alg))

	r, err := allocResources(store, algID, chunkSize)
	if err != nil {
		return nil, err
	}

	var flags C.uint8_t = C.AEGIS_RAF_CREATE
	if opts.Truncate {
		flags |= C.AEGIS_RAF_TRUNCATE
	}

	scratchSize := C.raf_scratch_size(algID, C.uint32_t(chunkSize))
	r.state.lastErr = nil
	ret, cerr := C.raf_do_create(algID, r.ctx, r.box,
		(*C.uint8_t)(r.scratch), scratchSize,
		C.uint32_t(chunkSize), flags, (*C.uint8_t)(&key[0]))
	if ret != 0 {
		e := mapErrno(cerr, r.state)
		r.free()
		return nil, e
	}

	return &File{
		ctx:        r.ctx,
		scratchBuf: r.scratch,
		handleBox:  r.box,
		cbState:    r.state,
		algID:      algID,
		chunkSize:  chunkSize,
	}, nil
}

// Open opens an existing encrypted file.
// The algorithm and chunk size are read from the file header.
//
// If the key is wrong or the header has been tampered with, Open returns
// ErrAuth. These two cases are indistinguishable by design.
func Open(store Store, key []byte, opts *Options) (*File, error) {
	// Probe the header to discover algorithm and chunk size.
	info, err := Probe(store)
	if err != nil {
		return nil, err
	}

	alg := info.Algorithm
	if len(key) != alg.KeySize() {
		return nil, ErrBadKeyLength
	}

	algID := C.int(cAlgID(alg))
	chunkSize := info.ChunkSize

	r, err := allocResources(store, algID, chunkSize)
	if err != nil {
		return nil, err
	}

	scratchSize := C.raf_scratch_size(algID, C.uint32_t(chunkSize))
	r.state.lastErr = nil
	ret, cerr := C.raf_do_open(algID, r.ctx, r.box,
		(*C.uint8_t)(r.scratch), scratchSize,
		C.uint32_t(chunkSize), (*C.uint8_t)(&key[0]))
	if ret != 0 {
		e := mapErrno(cerr, r.state)
		r.free()
		return nil, e
	}

	return &File{
		ctx:        r.ctx,
		scratchBuf: r.scratch,
		handleBox:  r.box,
		cbState:    r.state,
		algID:      algID,
		chunkSize:  chunkSize,
	}, nil
}

// Probe reads the file header without decrypting or verifying the MAC.
// Useful to discover the algorithm and chunk size before opening.
func Probe(store Store) (*FileInfo, error) {
	// Set up a temporary I/O bridge for the probe call.
	state := &callbackState{store: store}
	box := C.malloc(C.size_t(unsafe.Sizeof(C.uintptr_t(0))))
	if box == nil {
		return nil, fmt.Errorf("raf: failed to allocate handle box")
	}
	h := cgo.NewHandle(state)
	*(*C.uintptr_t)(box) = C.uintptr_t(h)

	var cinfo C.aegis_raf_info
	ret, cerr := C.raf_do_probe(box, &cinfo)

	h.Delete()
	C.free(box)

	if ret != 0 {
		return nil, mapErrno(cerr, state)
	}

	return &FileInfo{
		Size:      int64(cinfo.file_size),
		ChunkSize: int(cinfo.chunk_size),
		Algorithm: algFromCID(int(cinfo.alg_id)),
	}, nil
}

// ReadAt reads len(p) plaintext bytes starting at byte offset off.
// Implements io.ReaderAt.
func (f *File) ReadAt(p []byte, off int64) (int, error) {
	if f.closed {
		return 0, ErrClosed
	}
	if off < 0 {
		return 0, ErrNegativeOffset
	}
	if len(p) == 0 {
		return 0, nil
	}

	f.cbState.lastErr = nil
	var bytesRead C.size_t
	ret, cerr := C.raf_read(f.algID, f.ctx, (*C.uint8_t)(&p[0]), &bytesRead,
		C.size_t(len(p)), C.uint64_t(off))
	if ret != 0 {
		return int(bytesRead), mapErrno(cerr, f.cbState)
	}
	n := int(bytesRead)
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// WriteAt writes len(p) plaintext bytes starting at byte offset off.
// Implements io.WriterAt.
func (f *File) WriteAt(p []byte, off int64) (int, error) {
	if f.closed {
		return 0, ErrClosed
	}
	if off < 0 {
		return 0, ErrNegativeOffset
	}
	if len(p) == 0 {
		return 0, nil
	}

	f.cbState.lastErr = nil
	var bytesWritten C.size_t
	ret, cerr := C.raf_write(f.algID, f.ctx, &bytesWritten,
		(*C.uint8_t)(&p[0]), C.size_t(len(p)), C.uint64_t(off))
	if ret != 0 {
		return int(bytesWritten), mapErrno(cerr, f.cbState)
	}
	return int(bytesWritten), nil
}

// Truncate changes the logical plaintext size.
func (f *File) Truncate(size int64) error {
	if f.closed {
		return ErrClosed
	}
	if size < 0 {
		return ErrNegativeOffset
	}
	f.cbState.lastErr = nil
	ret, cerr := C.raf_truncate(f.algID, f.ctx, C.uint64_t(size))
	if ret != 0 {
		return mapErrno(cerr, f.cbState)
	}
	return nil
}

// Size returns the current logical plaintext size.
func (f *File) Size() (int64, error) {
	if f.closed {
		return 0, ErrClosed
	}
	var size C.uint64_t
	ret, cerr := C.raf_get_size(f.algID, f.ctx, &size)
	if ret != 0 {
		return 0, mapErrno(cerr, f.cbState)
	}
	return int64(size), nil
}

// Sync flushes writes to the backing store.
func (f *File) Sync() error {
	if f.closed {
		return ErrClosed
	}
	f.cbState.lastErr = nil
	ret, cerr := C.raf_sync(f.algID, f.ctx)
	if ret != 0 {
		return mapErrno(cerr, f.cbState)
	}
	return nil
}

// Close flushes, zeroizes keys, and releases all C-allocated resources.
func (f *File) Close() error {
	if f.closed {
		return ErrClosed
	}
	f.closed = true

	// Sync at the Go level so we can report failures.
	syncErr := f.cbState.store.Sync()

	// Disable the sync callback so raf_close's internal sync (which
	// is void and discards errors) doesn't issue a redundant call.
	f.cbState.syncDisabled = true

	// The C close function zeroizes the context.
	C.raf_close(f.algID, f.ctx)

	// Free C-allocated resources.
	handle := cgo.Handle(*(*C.uintptr_t)(f.handleBox))
	handle.Delete()
	C.free(f.handleBox)
	C.raf_aligned_free(f.ctx)
	C.raf_aligned_free(f.scratchBuf)

	f.ctx = nil
	f.scratchBuf = nil
	f.handleBox = nil
	f.cbState = nil

	if syncErr != nil {
		return fmt.Errorf("raf: %w", syncErr)
	}
	return nil
}

// Info returns metadata about the open file.
func (f *File) Info() FileInfo {
	size, _ := f.Size()
	return FileInfo{
		Size:      size,
		ChunkSize: f.chunkSize,
		Algorithm: algFromCID(int(f.algID)),
	}
}

// mapErrno converts a C errno (returned via CGO's multi-value form) to a Go error.
// If the errno is EIO (set by our callback shims), it returns the stashed
// Go error from the callbackState, giving callers the real Store error.
func mapErrno(err error, state *callbackState) error {
	if state != nil && state.lastErr != nil {
		stashed := state.lastErr
		state.lastErr = nil
		return fmt.Errorf("raf: %w", stashed)
	}
	e, ok := err.(syscall.Errno)
	if !ok {
		return fmt.Errorf("raf: %w", err)
	}
	switch e {
	case syscall.EBADMSG:
		return ErrAuth
	case syscall.EEXIST:
		return ErrExists
	case syscall.EOVERFLOW:
		return ErrOverflow
	case syscall.EINVAL:
		return ErrInvalidHeader
	default:
		return fmt.Errorf("raf: %w", e)
	}
}
