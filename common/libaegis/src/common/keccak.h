#ifndef keccak_H
#define keccak_H

#include <stddef.h>
#include <stdint.h>

void aegis_kdf_128(uint8_t *out, size_t outlen, const uint8_t *context, size_t context_len,
                   const uint8_t *key, size_t key_len, const uint8_t *file_id, size_t file_id_len);

void aegis_kdf_256(uint8_t *out, size_t outlen, const uint8_t *context, size_t context_len,
                   const uint8_t *key, size_t key_len, const uint8_t *file_id, size_t file_id_len);

#endif
