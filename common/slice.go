package common

// GrowSlice extends a slice to accommodate n additional bytes, avoiding double allocations.
// Returns:
//   - result: the extended slice (original content + n bytes) to return to caller
//   - tail: a view of the new n bytes where data should be written
//
// If the slice has sufficient capacity, it reslices in place.
// Otherwise, it allocates a new slice and copies the existing content.
func GrowSlice(s []byte, n int) (result, tail []byte) {
	if cap(s)-len(s) >= n {
		return s[:len(s)+n], s[len(s) : len(s)+n]
	}
	grown := make([]byte, len(s)+n)
	copy(grown, s)
	return grown, grown[len(s):]
}
