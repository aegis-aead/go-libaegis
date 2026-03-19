#include <stddef.h>
#include <stdint.h>

#include "raf_internal.h"

size_t
aegis_raf_chunk_min(void)
{
    return AEGIS_RAF_CHUNK_MIN;
}

size_t
aegis_raf_chunk_max(void)
{
    return AEGIS_RAF_CHUNK_MAX;
}

size_t
aegis_raf_header_size(void)
{
    return AEGIS_RAF_HEADER_SIZE;
}

size_t
aegis_raf_scratch_align(void)
{
    return AEGIS_RAF_SCRATCH_ALIGN;
}

int
aegis_raf_probe(const aegis_raf_io *io, aegis_raf_info *info)
{
    uint8_t  hdr[AEGIS_RAF_HEADER_SIZE];
    uint16_t header_size;
    uint8_t  version;
    uint32_t chunk_size;
    uint8_t  alg_id;

    if (io == NULL || info == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (io->read_at == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (io->read_at(io->user, hdr, AEGIS_RAF_HEADER_SIZE, 0) != 0) {
        return -1;
    }

    if (memcmp(hdr, AEGIS_RAF_MAGIC, 8) != 0) {
        errno = EINVAL;
        return -1;
    }

    header_size = LOAD16_LE(hdr + 8);
    if (header_size != AEGIS_RAF_HEADER_SIZE) {
        errno = EINVAL;
        return -1;
    }

    version = hdr[10];
    if (version != AEGIS_RAF_VERSION) {
        errno = EINVAL;
        return -1;
    }

    chunk_size = LOAD32_LE(hdr + 12);
    if (chunk_size < AEGIS_RAF_CHUNK_MIN || chunk_size > AEGIS_RAF_CHUNK_MAX ||
        (chunk_size % 16) != 0) {
        errno = EINVAL;
        return -1;
    }

    alg_id = hdr[11];
    if (alg_id < AEGIS_RAF_ALG_128L || alg_id > AEGIS_RAF_ALG_256X4) {
        errno = EINVAL;
        return -1;
    }

    info->alg_id     = alg_id;
    info->chunk_size = chunk_size;
    info->file_size  = LOAD64_LE(hdr + 16);

    return 0;
}
