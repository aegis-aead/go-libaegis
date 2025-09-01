//go:build cgo && go1.19
// +build cgo,go1.19

package common

import (
	"testing"
	"unsafe"
)

func TestAnyOverlap(t *testing.T) {
	tests := []struct {
		name     string
		x, y     []byte
		expected bool
	}{
		{"Empty slices", []byte{}, []byte{}, false},
		{"One empty slice", []byte{1, 2, 3}, []byte{}, false},
		{"Non-overlapping slices", []byte{1, 2, 3}, []byte{4, 5, 6}, false},
	}

	// Create overlapping slices manually
	baseSlice := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	slice1 := baseSlice[0:4] // [1, 2, 3, 4]
	slice2 := baseSlice[2:6] // [3, 4, 5, 6]
	tests = append(tests, struct {
		name     string
		x, y     []byte
		expected bool
	}{"Overlapping slices", slice1, slice2, true})

	// Create identical slices (same starting address)
	slice3 := baseSlice[1:4] // [2, 3, 4]
	slice4 := baseSlice[1:5] // [2, 3, 4, 5]
	tests = append(tests, struct {
		name     string
		x, y     []byte
		expected bool
	}{"Same start, different length", slice3, slice4, true})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnyOverlap(tt.x, tt.y)
			if result != tt.expected {
				t.Errorf("AnyOverlap(%v, %v) = %v, want %v", tt.x, tt.y, result, tt.expected)
			}
		})
	}
}

func TestInexactOverlap(t *testing.T) {
	tests := []struct {
		name     string
		x, y     []byte
		expected bool
	}{
		{"Empty slices", []byte{}, []byte{}, false},
		{"One empty slice", []byte{1, 2, 3}, []byte{}, false},
		{"Non-overlapping slices", []byte{1, 2, 3}, []byte{4, 5, 6}, false},
	}

	// Create test slices
	baseSlice := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	// Same starting address - should return false (exact overlap)
	slice1 := baseSlice[1:4] // [2, 3, 4]
	slice2 := baseSlice[1:5] // [2, 3, 4, 5]
	tests = append(tests, struct {
		name     string
		x, y     []byte
		expected bool
	}{"Same start address - exact overlap", slice1, slice2, false})

	// Different starting addresses but overlapping - should return true (inexact overlap)
	slice3 := baseSlice[0:4] // [1, 2, 3, 4]
	slice4 := baseSlice[2:6] // [3, 4, 5, 6]
	tests = append(tests, struct {
		name     string
		x, y     []byte
		expected bool
	}{"Overlapping different starts - inexact overlap", slice3, slice4, true})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := InexactOverlap(tt.x, tt.y)
			if result != tt.expected {
				t.Errorf("InexactOverlap(%v, %v) = %v, want %v", tt.x, tt.y, result, tt.expected)
			}
		})
	}
}

func TestBufferOverlapDetection(t *testing.T) {
	// Test the exact scenarios described in the PR

	// Create a base buffer for testing
	baseBuffer := make([]byte, 100)

	// Test case 1: Destination and source have inexact overlap
	dst1 := baseBuffer[0:50]
	src1 := baseBuffer[10:60]

	if !InexactOverlap(dst1, src1) {
		t.Error("Expected InexactOverlap to detect overlap between dst and src")
	}

	// Test case 2: Destination and source are exactly the same
	dst2 := baseBuffer[20:70]
	src2 := baseBuffer[20:70]

	if InexactOverlap(dst2, src2) {
		t.Error("Expected InexactOverlap to return false for identical slices")
	}

	// Test case 3: No overlap
	dst3 := baseBuffer[0:30]
	src3 := baseBuffer[70:100]

	if InexactOverlap(dst3, src3) {
		t.Error("Expected InexactOverlap to return false for non-overlapping slices")
	}
}

func TestMemoryAddressComparison(t *testing.T) {
	// Verify that our implementation matches the expected behavior
	// by manually checking memory addresses

	slice := make([]byte, 20)

	// Same starting address
	a := slice[5:10]
	b := slice[5:15]

	if &a[0] != &b[0] {
		t.Fatal("Test setup error: expected same starting address")
	}

	if InexactOverlap(a, b) {
		t.Error("InexactOverlap should return false for same starting address")
	}

	// Different starting addresses, overlapping
	c := slice[3:8]
	d := slice[6:12]

	if &c[0] == &d[0] {
		t.Fatal("Test setup error: expected different starting addresses")
	}

	// Verify they overlap by checking address ranges
	c0 := uintptr(unsafe.Pointer(&c[0]))
	c1 := c0 + uintptr(len(c))
	d0 := uintptr(unsafe.Pointer(&d[0]))
	d1 := d0 + uintptr(len(d))

	overlaps := c0 < d1 && d0 < c1
	if !overlaps {
		t.Fatal("Test setup error: slices should overlap")
	}

	if !InexactOverlap(c, d) {
		t.Error("InexactOverlap should return true for inexact overlap")
	}
}
