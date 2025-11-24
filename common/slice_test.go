package common

import (
	"bytes"
	"testing"
)

func TestGrowSlice(t *testing.T) {
	t.Run("sufficient capacity", func(t *testing.T) {
		// Slice with extra capacity
		original := make([]byte, 10, 50)
		for i := range original {
			original[i] = byte(i)
		}

		result, tail := GrowSlice(original, 20)

		// Should reuse the same backing array
		if cap(result) != 50 {
			t.Errorf("expected capacity 50, got %d", cap(result))
		}
		if len(result) != 30 {
			t.Errorf("expected length 30, got %d", len(result))
		}
		if len(tail) != 20 {
			t.Errorf("expected tail length 20, got %d", len(tail))
		}
		// Verify original content preserved
		if !bytes.Equal(result[:10], original[:10]) {
			t.Error("original content not preserved")
		}
		// Verify tail points to the right location
		if &result[10] != &tail[0] {
			t.Error("tail does not point to correct location")
		}
	})

	t.Run("insufficient capacity", func(t *testing.T) {
		// Slice without enough capacity
		original := make([]byte, 10, 15)
		for i := range original {
			original[i] = byte(i)
		}

		result, tail := GrowSlice(original, 20)

		// Should allocate new slice
		if len(result) != 30 {
			t.Errorf("expected length 30, got %d", len(result))
		}
		if len(tail) != 20 {
			t.Errorf("expected tail length 20, got %d", len(tail))
		}
		// Verify original content copied
		if !bytes.Equal(result[:10], original[:10]) {
			t.Error("original content not copied")
		}
		// Verify tail points to the right location
		if &result[10] != &tail[0] {
			t.Error("tail does not point to correct location")
		}
	})

	t.Run("nil slice", func(t *testing.T) {
		result, tail := GrowSlice(nil, 10)

		if len(result) != 10 {
			t.Errorf("expected length 10, got %d", len(result))
		}
		if len(tail) != 10 {
			t.Errorf("expected tail length 10, got %d", len(tail))
		}
		if &result[0] != &tail[0] {
			t.Error("result and tail should start at same address for nil input")
		}
	})

	t.Run("zero growth", func(t *testing.T) {
		original := []byte{1, 2, 3}
		result, tail := GrowSlice(original, 0)

		if len(result) != 3 {
			t.Errorf("expected length 3, got %d", len(result))
		}
		if len(tail) != 0 {
			t.Errorf("expected tail length 0, got %d", len(tail))
		}
	})
}

// BenchmarkGrowSlice compares the optimized GrowSlice approach
// against the old double-allocation pattern.
func BenchmarkGrowSlice(b *testing.B) {
	sizes := []int{64, 1024, 16384}

	for _, size := range sizes {
		// Benchmark the scenario where dst has insufficient capacity
		// (the case that was causing double allocations)
		b.Run("insufficient_cap/"+sizeStr(size), func(b *testing.B) {
			dst := make([]byte, 16, 16) // small capacity, simulates prefix data
			for i := range dst {
				dst[i] = byte(i)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				full, tail := GrowSlice(dst, size)
				_ = full
				_ = tail
			}
		})

		// Benchmark the scenario where dst has sufficient capacity
		b.Run("sufficient_cap/"+sizeStr(size), func(b *testing.B) {
			dst := make([]byte, 16, 16+size+100)
			for i := range dst {
				dst[i] = byte(i)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				full, tail := GrowSlice(dst, size)
				_ = full
				_ = tail
			}
		})
	}
}

// BenchmarkOldPattern benchmarks the old double-allocation pattern
// to demonstrate the improvement.
func BenchmarkOldPattern(b *testing.B) {
	sizes := []int{64, 1024, 16384}

	for _, size := range sizes {
		b.Run("insufficient_cap/"+sizeStr(size), func(b *testing.B) {
			dst := make([]byte, 16, 16)
			for i := range dst {
				dst[i] = byte(i)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Old pattern: allocate temp buffer, then append
				var buf []byte
				if cap(dst)-len(dst) >= size {
					buf = dst[len(dst) : len(dst)+size]
					_ = dst[:len(dst)+size]
				} else {
					buf = make([]byte, size) // first allocation
					_ = append(dst, buf...)  // second allocation
				}
				_ = buf
			}
		})

		b.Run("sufficient_cap/"+sizeStr(size), func(b *testing.B) {
			dst := make([]byte, 16, 16+size+100)
			for i := range dst {
				dst[i] = byte(i)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var buf []byte
				if cap(dst)-len(dst) >= size {
					buf = dst[len(dst) : len(dst)+size]
					_ = dst[:len(dst)+size]
				} else {
					buf = make([]byte, size)
					_ = append(dst, buf...)
				}
				_ = buf
			}
		})
	}
}

func sizeStr(size int) string {
	switch {
	case size >= 1024*1024:
		return string(rune('0'+size/(1024*1024))) + "MB"
	case size >= 1024:
		return string(rune('0'+size/1024)) + "KB"
	default:
		return string(rune('0'+size/10)) + string(rune('0'+size%10)) + "B"
	}
}
