package raf

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/aegis-aead/go-libaegis/common"
)

// Known-answer vectors from the upstream libaegis test suite
func TestDeriveMasterKeyVectors(t *testing.T) {
	if !common.Available {
		t.Skip("CGO not available")
	}

	vectors := []struct {
		name      string
		masterKey string
		context   string
		want      string
	}{
		{
			name:      "128-bit",
			masterKey: "000102030405060708090a0b0c0d0e0f",
			context:   "test-context",
			want:      "fb80072c5a6f1cddc6e97b35ed1f3bf3",
		},
		{
			name:      "256-bit",
			masterKey: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			context:   "test-context",
			want:      "fee2d3cc58c69d8f43fd7b4e33eaec0053539685c7e284e6e12ee9c4f423d136",
		},
	}

	for _, tc := range vectors {
		t.Run(tc.name, func(t *testing.T) {
			masterKey, err := hex.DecodeString(tc.masterKey)
			if err != nil {
				t.Fatalf("bad master key vector: %v", err)
			}

			got, err := DeriveMasterKey(masterKey, tc.context)
			if err != nil {
				t.Fatalf("DeriveMasterKey: %v", err)
			}
			if hex.EncodeToString(got) != tc.want {
				t.Fatalf("derived %x, want %s", got, tc.want)
			}
		})
	}
}

func TestDeriveMasterKeyDeterministic(t *testing.T) {
	if !common.Available {
		t.Skip("CGO not available")
	}

	for _, keyLen := range []int{16, 32} {
		master := make([]byte, keyLen)
		rand.Read(master)

		first, err := DeriveMasterKey(master, "backups")
		if err != nil {
			t.Fatalf("DeriveMasterKey: %v", err)
		}
		second, err := DeriveMasterKey(master, "backups")
		if err != nil {
			t.Fatalf("DeriveMasterKey: %v", err)
		}
		if !bytes.Equal(first, second) {
			t.Fatalf("key length %d: derivation is not deterministic", keyLen)
		}
		if len(first) != keyLen {
			t.Fatalf("key length %d: derived %d bytes", keyLen, len(first))
		}
		if bytes.Equal(first, master) {
			t.Fatalf("key length %d: derived key equals the master key", keyLen)
		}
	}
}

func TestDeriveMasterKeySeparation(t *testing.T) {
	if !common.Available {
		t.Skip("CGO not available")
	}

	master := make([]byte, 32)
	rand.Read(master)

	empty, err := DeriveMasterKey(master, "")
	if err != nil {
		t.Fatalf("DeriveMasterKey with empty context: %v", err)
	}
	if bytes.Equal(empty, master) {
		t.Fatal("empty context passed the master key through unchanged")
	}

	a, err := DeriveMasterKey(master, "photos")
	if err != nil {
		t.Fatalf("DeriveMasterKey: %v", err)
	}
	b, err := DeriveMasterKey(master, "videos")
	if err != nil {
		t.Fatalf("DeriveMasterKey: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("different contexts produced the same key")
	}
	if bytes.Equal(a, empty) {
		t.Fatal("non-empty context matched the empty one")
	}

	other := make([]byte, 32)
	rand.Read(other)
	c, err := DeriveMasterKey(other, "photos")
	if err != nil {
		t.Fatalf("DeriveMasterKey: %v", err)
	}
	if bytes.Equal(a, c) {
		t.Fatal("different master keys produced the same key")
	}
}

func TestDeriveMasterKeyErrors(t *testing.T) {
	if !common.Available {
		t.Skip("CGO not available")
	}

	if _, err := DeriveMasterKey(make([]byte, 24), "ctx"); err != ErrBadKeyLength {
		t.Fatalf("24-byte master key: got %v, want ErrBadKeyLength", err)
	}
	if _, err := DeriveMasterKey(nil, "ctx"); err != ErrBadKeyLength {
		t.Fatalf("nil master key: got %v, want ErrBadKeyLength", err)
	}

	for _, keyLen := range []int{16, 32} {
		max := MaxContextLen(keyLen)
		master := make([]byte, keyLen)

		if _, err := DeriveMasterKey(master, strings.Repeat("x", max)); err != nil {
			t.Fatalf("key length %d: context of %d bytes rejected: %v", keyLen, max, err)
		}
		if _, err := DeriveMasterKey(master, strings.Repeat("x", max+1)); err != ErrContextTooLong {
			t.Fatalf("key length %d: got %v, want ErrContextTooLong", keyLen, err)
		}
	}

	if n := MaxContextLen(24); n != 0 {
		t.Fatalf("MaxContextLen(24) = %d, want 0", n)
	}
}

// A derived key is a normal RAF key: it must open a file it created, and the
// master key it came from must not.
func TestDeriveMasterKeyUsable(t *testing.T) {
	if !common.Available {
		t.Skip("CGO not available")
	}

	master := make([]byte, 16)
	rand.Read(master)

	derived, err := DeriveMasterKey(master, "archive")
	if err != nil {
		t.Fatalf("DeriveMasterKey: %v", err)
	}

	store := newMemStore()
	f, err := Create(store, derived, &Options{Algorithm: AEGIS128L, ChunkSize: MinChunkSize})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	want := []byte("derived key round trip")
	if _, err := f.WriteAt(want, 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err = Open(store, derived, nil)
	if err != nil {
		t.Fatalf("Open with derived key: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := f.ReadAt(got, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("read %q, want %q", got, want)
	}
	f.Close()

	if _, err := Open(store, master, nil); err != ErrAuth {
		t.Fatalf("Open with the master key: got %v, want ErrAuth", err)
	}
}
