package common

import (
	_ "embed"
	"testing"
)

func TestOverhead(t *testing.T) {
	if !Available {
		return
	}
	aead := Aegis{TagLen: 16}
	if aead.Overhead() != aead.TagLen {
		panic("Unexpected overhead")
	}
	aead.Wipe()
}

//go:embed libaegis/src/aegis256x2/aegis256x2_aesni.h
var _ []byte

//go:embed libaegis/src/aegis256x2/aegis256x2_common.h
var _ []byte

//go:embed libaegis/src/aegis256x2/aegis256x2_soft.h
var _ []byte

//go:embed libaegis/src/aegis256x2/aegis256x2_altivec.h
var _ []byte

//go:embed libaegis/src/aegis256x2/implementations.h
var _ []byte

//go:embed libaegis/src/aegis256x2/aegis256x2_avx2.h
var _ []byte

//go:embed libaegis/src/aegis256x2/aegis256x2_neon_aes.h
var _ []byte

//go:embed libaegis/src/aegis256x4/aegis256x4_common.h
var _ []byte

//go:embed libaegis/src/aegis256x4/aegis256x4_altivec.h
var _ []byte

//go:embed libaegis/src/aegis256x4/aegis256x4_neon_aes.h
var _ []byte

//go:embed libaegis/src/aegis256x4/aegis256x4_avx2.h
var _ []byte

//go:embed libaegis/src/aegis256x4/aegis256x4_avx512.h
var _ []byte

//go:embed libaegis/src/aegis256x4/implementations.h
var _ []byte

//go:embed libaegis/src/aegis256x4/aegis256x4_soft.h
var _ []byte

//go:embed libaegis/src/aegis256x4/aegis256x4_aesni.h
var _ []byte

//go:embed libaegis/src/include/aegis256x2.h
var _ []byte

//go:embed libaegis/src/include/aegis128x4.h
var _ []byte

//go:embed libaegis/src/include/aegis128l.h
var _ []byte

//go:embed libaegis/src/include/aegis256x4.h
var _ []byte

//go:embed libaegis/src/include/aegis256.h
var _ []byte

//go:embed libaegis/src/include/aegis.h
var _ []byte

//go:embed libaegis/src/include/aegis128x2.h
var _ []byte

//go:embed libaegis/src/aegis128l/aegis128l_neon_aes.h
var _ []byte

//go:embed libaegis/src/aegis128l/aegis128l_neon_sha3.h
var _ []byte

//go:embed libaegis/src/aegis128l/aegis128l_aesni.h
var _ []byte

//go:embed libaegis/src/aegis128l/aegis128l_soft.h
var _ []byte

//go:embed libaegis/src/aegis128l/aegis128l_common.h
var _ []byte

//go:embed libaegis/src/aegis128l/aegis128l_altivec.h
var _ []byte

//go:embed libaegis/src/aegis128l/implementations.h
var _ []byte

//go:embed libaegis/src/common/softaes.h
var _ []byte

//go:embed libaegis/src/common/common.h
var _ []byte

//go:embed libaegis/src/common/cpu.h
var _ []byte

//go:embed libaegis/src/aegis256/aegis256_altivec.h
var _ []byte

//go:embed libaegis/src/aegis256/aegis256_aesni.h
var _ []byte

//go:embed libaegis/src/aegis256/aegis256_common.h
var _ []byte

//go:embed libaegis/src/aegis256/implementations.h
var _ []byte

//go:embed libaegis/src/aegis256/aegis256_neon_aes.h
var _ []byte

//go:embed libaegis/src/aegis256/aegis256_soft.h
var _ []byte

//go:embed libaegis/src/aegis128x4/aegis128x4_avx512.h
var _ []byte

//go:embed libaegis/src/aegis128x4/aegis128x4_aesni.h
var _ []byte

//go:embed libaegis/src/aegis128x4/aegis128x4_altivec.h
var _ []byte

//go:embed libaegis/src/aegis128x4/aegis128x4_neon_aes.h
var _ []byte

//go:embed libaegis/src/aegis128x4/aegis128x4_soft.h
var _ []byte

//go:embed libaegis/src/aegis128x4/aegis128x4_common.h
var _ []byte

//go:embed libaegis/src/aegis128x4/implementations.h
var _ []byte

//go:embed libaegis/src/aegis128x4/aegis128x4_avx2.h
var _ []byte

//go:embed libaegis/src/aegis128x2/aegis128x2_neon_aes.h
var _ []byte

//go:embed libaegis/src/aegis128x2/aegis128x2_altivec.h
var _ []byte

//go:embed libaegis/src/aegis128x2/aegis128x2_aesni.h
var _ []byte

//go:embed libaegis/src/aegis128x2/aegis128x2_avx2.h
var _ []byte

//go:embed libaegis/src/aegis128x2/aegis128x2_common.h
var _ []byte

//go:embed libaegis/src/aegis128x2/aegis128x2_soft.h
var _ []byte

//go:embed libaegis/src/aegis128x2/implementations.h
var _ []byte

//go:embed libaegis/src/aegis256x2/aegis256x2_altivec.c
var _ []byte

//go:embed libaegis/src/aegis256x2/aegis256x2_soft.c
var _ []byte

//go:embed libaegis/src/aegis256x2/aegis256x2_neon_aes.c
var _ []byte

//go:embed libaegis/src/aegis256x2/aegis256x2_avx2.c
var _ []byte

//go:embed libaegis/src/aegis256x2/aegis256x2.c
var _ []byte

//go:embed libaegis/src/aegis256x2/aegis256x2_aesni.c
var _ []byte

//go:embed libaegis/src/aegis256x4/aegis256x4_altivec.c
var _ []byte

//go:embed libaegis/src/aegis256x4/aegis256x4_neon_aes.c
var _ []byte

//go:embed libaegis/src/aegis256x4/aegis256x4_avx2.c
var _ []byte

//go:embed libaegis/src/aegis256x4/aegis256x4.c
var _ []byte

//go:embed libaegis/src/aegis256x4/aegis256x4_avx512.c
var _ []byte

//go:embed libaegis/src/aegis256x4/aegis256x4_soft.c
var _ []byte

//go:embed libaegis/src/aegis256x4/aegis256x4_aesni.c
var _ []byte

//go:embed libaegis/src/aegis128l/aegis128l_soft.c
var _ []byte

//go:embed libaegis/src/aegis128l/aegis128l_altivec.c
var _ []byte

//go:embed libaegis/src/aegis128l/aegis128l_aesni.c
var _ []byte

//go:embed libaegis/src/aegis128l/aegis128l_neon_aes.c
var _ []byte

//go:embed libaegis/src/aegis128l/aegis128l_neon_sha3.c
var _ []byte

//go:embed libaegis/src/aegis128l/aegis128l.c
var _ []byte

//go:embed libaegis/src/common/common.c
var _ []byte

//go:embed libaegis/src/common/cpu.c
var _ []byte

//go:embed libaegis/src/common/softaes.c
var _ []byte

//go:embed libaegis/src/aegis256/aegis256.c
var _ []byte

//go:embed libaegis/src/aegis256/aegis256_soft.c
var _ []byte

//go:embed libaegis/src/aegis256/aegis256_neon_aes.c
var _ []byte

//go:embed libaegis/src/aegis256/aegis256_aesni.c
var _ []byte

//go:embed libaegis/src/aegis256/aegis256_altivec.c
var _ []byte

//go:embed libaegis/src/aegis128x4/aegis128x4_soft.c
var _ []byte

//go:embed libaegis/src/aegis128x4/aegis128x4_avx2.c
var _ []byte

//go:embed libaegis/src/aegis128x4/aegis128x4_avx512.c
var _ []byte

//go:embed libaegis/src/aegis128x4/aegis128x4_aesni.c
var _ []byte

//go:embed libaegis/src/aegis128x4/aegis128x4_altivec.c
var _ []byte

//go:embed libaegis/src/aegis128x4/aegis128x4_neon_aes.c
var _ []byte

//go:embed libaegis/src/aegis128x4/aegis128x4.c
var _ []byte

//go:embed libaegis/src/aegis128x2/aegis128x2_aesni.c
var _ []byte

//go:embed libaegis/src/aegis128x2/aegis128x2_avx2.c
var _ []byte

//go:embed libaegis/src/aegis128x2/aegis128x2.c
var _ []byte

//go:embed libaegis/src/aegis128x2/aegis128x2_soft.c
var _ []byte

//go:embed libaegis/src/aegis128x2/aegis128x2_neon_aes.c
var _ []byte

//go:embed libaegis/src/aegis128x2/aegis128x2_altivec.c
var _ []byte

//go:embed libaegis/LICENSE
var _ []byte
