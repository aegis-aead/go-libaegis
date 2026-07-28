#include <stddef.h>
#include <stdint.h>

#include "../common/keccak.h"
#include "raf_internal.h"

#define RAF_KDF_CONTEXT     "aegis-raf-master-key-v1"
#define RAF_KDF_CONTEXT_LEN 23

#define FILE_ID_PREFIX_LEN 8
#define KDF_128_RATE       168
#define KDF_256_RATE       136

#define MAX_CONTEXT_LEN_128 (KDF_128_RATE - 1 - RAF_KDF_CONTEXT_LEN - 16 - FILE_ID_PREFIX_LEN)
#define MAX_CONTEXT_LEN_256 (KDF_256_RATE - 1 - RAF_KDF_CONTEXT_LEN - 32 - FILE_ID_PREFIX_LEN)

int
aegis_raf_derive_master_key(uint8_t *out, size_t out_len, const uint8_t *master_key,
                            size_t master_key_len, const uint8_t *context, size_t context_len)
{
    uint8_t file_id_buf[FILE_ID_PREFIX_LEN + MAX_CONTEXT_LEN_128];
    size_t  max_context_len;

    if (out == NULL || master_key == NULL) {
        errno = EINVAL;
        return -1;
    }
    if ((out_len != 16 && out_len != 32) || (master_key_len != 16 && master_key_len != 32) ||
        out_len != master_key_len) {
        errno = EINVAL;
        return -1;
    }
    if (context == NULL && context_len > 0) {
        errno = EINVAL;
        return -1;
    }

    max_context_len = (master_key_len == 16) ? MAX_CONTEXT_LEN_128 : MAX_CONTEXT_LEN_256;
    if (context_len > max_context_len) {
        errno = EINVAL;
        return -1;
    }

    STORE64_LE(file_id_buf, (uint64_t) context_len);
    if (context_len > 0) {
        memcpy(file_id_buf + FILE_ID_PREFIX_LEN, context, context_len);
    }

    if (master_key_len == 16) {
        aegis_kdf_128(out, out_len, (const uint8_t *) RAF_KDF_CONTEXT, RAF_KDF_CONTEXT_LEN,
                      master_key, master_key_len, file_id_buf, FILE_ID_PREFIX_LEN + context_len);
    } else {
        aegis_kdf_256(out, out_len, (const uint8_t *) RAF_KDF_CONTEXT, RAF_KDF_CONTEXT_LEN,
                      master_key, master_key_len, file_id_buf, FILE_ID_PREFIX_LEN + context_len);
    }

    memset(file_id_buf, 0, sizeof file_id_buf);

    return 0;
}
