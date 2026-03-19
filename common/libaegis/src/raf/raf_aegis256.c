#include <stddef.h>
#include <stdint.h>

#include "raf_internal.h"

#include "../include/aegis256.h"

#define VARIANT   aegis256
#define KEYBYTES  aegis256_KEYBYTES
#define NPUBBYTES aegis256_NPUBBYTES
#define ALG_ID    AEGIS_RAF_ALG_256

#define VARIANT_encrypt_detached aegis256_encrypt_detached
#define VARIANT_decrypt_detached aegis256_decrypt_detached
#define VARIANT_mac_init         aegis256_mac_init
#define VARIANT_mac_update       aegis256_mac_update
#define VARIANT_mac_final        aegis256_mac_final
#define VARIANT_mac_verify       aegis256_mac_verify

#include "raf_variant.h"
