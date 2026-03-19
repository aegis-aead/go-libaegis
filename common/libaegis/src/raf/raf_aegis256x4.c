#include <stddef.h>
#include <stdint.h>

#include "raf_internal.h"

#include "../include/aegis256x4.h"

#define VARIANT   aegis256x4
#define KEYBYTES  aegis256x4_KEYBYTES
#define NPUBBYTES aegis256x4_NPUBBYTES
#define ALG_ID    AEGIS_RAF_ALG_256X4

#define VARIANT_encrypt_detached aegis256x4_encrypt_detached
#define VARIANT_decrypt_detached aegis256x4_decrypt_detached
#define VARIANT_mac_init         aegis256x4_mac_init
#define VARIANT_mac_update       aegis256x4_mac_update
#define VARIANT_mac_final        aegis256x4_mac_final
#define VARIANT_mac_verify       aegis256x4_mac_verify

#include "raf_variant.h"
