#include <stddef.h>
#include <stdint.h>

#include "raf_internal.h"

#include "../include/aegis128x4.h"

#define VARIANT   aegis128x4
#define KEYBYTES  aegis128x4_KEYBYTES
#define NPUBBYTES aegis128x4_NPUBBYTES
#define ALG_ID    AEGIS_RAF_ALG_128X4

#define VARIANT_encrypt_detached aegis128x4_encrypt_detached
#define VARIANT_decrypt_detached aegis128x4_decrypt_detached
#define VARIANT_mac_init         aegis128x4_mac_init
#define VARIANT_mac_update       aegis128x4_mac_update
#define VARIANT_mac_final        aegis128x4_mac_final
#define VARIANT_mac_verify       aegis128x4_mac_verify

#include "raf_variant.h"
