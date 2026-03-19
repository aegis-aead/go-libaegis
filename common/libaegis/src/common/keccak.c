#include "keccak.h"
#include "common.h"

#define KECCAK_ROUNDS 12

static inline uint64_t
ROTL64(uint64_t x, int b)
{
    return (x << b) | (x >> (64 - b));
}

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

static void
keccakf(uint64_t st[25])
{
    int      round;
    int      i;
    int      j;
    uint64_t t;
    uint64_t bc[5];

    for (round = 24 - KECCAK_ROUNDS; round < 24; round++) {
        /* Theta */
        for (i = 0; i < 5; i++) {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5) {
                st[j + i] ^= t;
            }
        }

        /* Rho Pi */
        t = st[1];
        {
            static const int piln[24] = {
                10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
                15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1,
            };
            static const int rotc[24] = {
                1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
                27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44,
            };
            for (i = 0; i < 24; i++) {
                j     = piln[i];
                bc[0] = st[j];
                st[j] = ROTL64(t, rotc[i]);
                t     = bc[0];
            }
        }

        /* Chi */
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++) {
                bc[i] = st[j + i];
            }
            for (i = 0; i < 5; i++) {
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }

        /* Iota */
        st[0] ^= RC[round];
    }
}

static inline uint64_t
load64_le(const uint8_t src[8])
{
    uint64_t w;
    w = (uint64_t) src[0];
    w |= (uint64_t) src[1] << 8;
    w |= (uint64_t) src[2] << 16;
    w |= (uint64_t) src[3] << 24;
    w |= (uint64_t) src[4] << 32;
    w |= (uint64_t) src[5] << 40;
    w |= (uint64_t) src[6] << 48;
    w |= (uint64_t) src[7] << 56;
    return w;
}

static inline void
store64_le(uint8_t dst[8], uint64_t w)
{
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
}

static void
keccak_absorb_once(uint64_t st[25], size_t rate, const uint8_t *in, size_t inlen)
{
    size_t i;

    memset(st, 0, 25 * sizeof(uint64_t));
    for (i = 0; i + 8 <= inlen; i += 8) {
        st[i / 8] ^= load64_le(in + i);
    }
    if (i < inlen) {
        uint8_t tail[8];
        size_t  rem = inlen - i;
        memset(tail, 0, sizeof tail);
        memcpy(tail, in + i, rem);
        st[i / 8] ^= load64_le(tail);
    }
    st[inlen / 8] ^= (uint64_t) 0x1F << (8 * (inlen % 8));
    st[(rate - 1) / 8] ^= (uint64_t) 0x80 << (8 * ((rate - 1) % 8));
    keccakf(st);
}

static void
keccak_squeeze_once(uint8_t *out, size_t outlen, const uint64_t st[25])
{
    size_t i;

    for (i = 0; i + 8 <= outlen; i += 8) {
        store64_le(out + i, st[i / 8]);
    }
    if (i < outlen) {
        uint8_t tail[8];
        store64_le(tail, st[i / 8]);
        memcpy(out + i, tail, outlen - i);
    }
}

void
aegis_kdf_128(uint8_t *out, size_t outlen, const uint8_t *context, size_t context_len,
              const uint8_t *key, size_t key_len, const uint8_t *file_id, size_t file_id_len)
{
    uint64_t st[25];
    uint8_t  buf[168];
    size_t   total = context_len + key_len + file_id_len;

    if (total >= 168 || outlen > 168) {
        memset(out, 0, outlen);
        return;
    }

    memcpy(buf, context, context_len);
    memcpy(buf + context_len, key, key_len);
    memcpy(buf + context_len + key_len, file_id, file_id_len);

    keccak_absorb_once(st, 168, buf, total);
    keccak_squeeze_once(out, outlen, st);
}

void
aegis_kdf_256(uint8_t *out, size_t outlen, const uint8_t *context, size_t context_len,
              const uint8_t *key, size_t key_len, const uint8_t *file_id, size_t file_id_len)
{
    uint64_t st[25];
    uint8_t  buf[136];
    size_t   total = context_len + key_len + file_id_len;

    if (total >= 136 || outlen > 136) {
        memset(out, 0, outlen);
        return;
    }

    memcpy(buf, context, context_len);
    memcpy(buf + context_len, key, key_len);
    memcpy(buf + context_len + key_len, file_id, file_id_len);

    keccak_absorb_once(st, 136, buf, total);
    keccak_squeeze_once(out, outlen, st);
}
