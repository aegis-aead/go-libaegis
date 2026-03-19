#ifndef raf_internal_H
#define raf_internal_H

#include <stddef.h>
#include <stdint.h>

#include "../common/common.h"
#include "../include/aegis_raf.h"
#include "raf_merkle.h"

#ifndef EBADMSG
#    define EBADMSG 77
#endif

#ifndef EINVAL
#    define EINVAL 22
#endif

#ifndef EEXIST
#    define EEXIST 17
#endif

#ifndef ENOENT
#    define ENOENT 2
#endif

#ifndef ENOMEM
#    define ENOMEM 12
#endif

#ifndef EOVERFLOW
#    define EOVERFLOW 75
#endif

#ifndef ENOTSUP
#    define ENOTSUP 95
#endif

static const uint8_t AEGIS_RAF_MAGIC[8] = { 'A', 'E', 'G', 'I', 'S', 'R', 'A', 'F' };

#define AEGIS_RAF_VERSION 1

typedef struct aegis_raf_ctx_internal {
    aegis_raf_io            io;
    aegis_raf_rng           rng;
    uint8_t                *scratch_buf;
    size_t                  scratch_len;
    uint8_t                *record_buf;
    uint8_t                *chunk_buf;
    size_t                  record_buf_size;
    size_t                  chunk_buf_size;
    size_t                  keybytes;
    size_t                  npubbytes;
    aegis_raf_merkle_config merkle_cfg;
    uint64_t                file_size;
    uint8_t                 enc_key[32];
    uint8_t                 hdr_key[32];
    uint8_t                 file_id[AEGIS_RAF_FILE_ID_BYTES];
    uint32_t                chunk_size;
    int                     merkle_enabled;
    uint8_t                 alg_id;
    uint8_t                 version;
} aegis_raf_ctx_internal;

#define LOAD64_LE(SRC) load64_le(SRC)
static inline uint64_t
load64_le(const uint8_t src[8])
{
#ifdef NATIVE_LITTLE_ENDIAN
    uint64_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint64_t w = (uint64_t) src[0];
    w |= (uint64_t) src[1] << 8;
    w |= (uint64_t) src[2] << 16;
    w |= (uint64_t) src[3] << 24;
    w |= (uint64_t) src[4] << 32;
    w |= (uint64_t) src[5] << 40;
    w |= (uint64_t) src[6] << 48;
    w |= (uint64_t) src[7] << 56;
    return w;
#endif
}

#define STORE64_LE(DST, W) store64_le((DST), (W))
static inline void
store64_le(uint8_t dst[8], uint64_t w)
{
#ifdef NATIVE_LITTLE_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[0] = (uint8_t) w;
    w >>= 8;
    dst[1] = (uint8_t) w;
    w >>= 8;
    dst[2] = (uint8_t) w;
    w >>= 8;
    dst[3] = (uint8_t) w;
    w >>= 8;
    dst[4] = (uint8_t) w;
    w >>= 8;
    dst[5] = (uint8_t) w;
    w >>= 8;
    dst[6] = (uint8_t) w;
    w >>= 8;
    dst[7] = (uint8_t) w;
#endif
}

#define STORE16_LE(DST, W) store16_le((DST), (W))
static inline void
store16_le(uint8_t dst[2], uint16_t w)
{
    dst[0] = (uint8_t) w;
    dst[1] = (uint8_t) (w >> 8);
}

#define LOAD16_LE(SRC) load16_le(SRC)
static inline uint16_t
load16_le(const uint8_t src[2])
{
    return (uint16_t) src[0] | ((uint16_t) src[1] << 8);
}

#define AAD_BYTES (AEGIS_RAF_FILE_ID_BYTES + 8 + 4)

static inline void
build_aad(uint8_t aad[AAD_BYTES], const uint8_t file_id[AEGIS_RAF_FILE_ID_BYTES],
          uint64_t chunk_idx, uint32_t chunk_size)
{
    memcpy(aad, file_id, AEGIS_RAF_FILE_ID_BYTES);
    STORE64_LE(aad + AEGIS_RAF_FILE_ID_BYTES, chunk_idx);
    STORE32_LE(aad + AEGIS_RAF_FILE_ID_BYTES + 8, chunk_size);
}

static inline void
build_commitment_context(uint8_t       out[AEGIS_RAF_COMMITMENT_CONTEXT_BYTES],
                         uint8_t       version,
                         uint8_t       alg_id,
                         uint32_t      chunk_size,
                         const uint8_t file_id[AEGIS_RAF_FILE_ID_BYTES])
{
    out[0] = version;
    out[1] = alg_id;
    STORE32_LE(out + 2, chunk_size);
    memcpy(out + 6, file_id, AEGIS_RAF_FILE_ID_BYTES);
    out[30] = 0;
    out[31] = 0;
}

#endif
