#include <stddef.h>
#include <stdint.h>

#include "raf_internal.h"

#include "../include/aegis256x2.h"

#define VARIANT   aegis256x2
#define KEYBYTES  aegis256x2_KEYBYTES
#define NPUBBYTES aegis256x2_NPUBBYTES
#define ALG_ID    AEGIS_RAF_ALG_256X2

#define VARIANT_encrypt_detached aegis256x2_encrypt_detached
#define VARIANT_decrypt_detached aegis256x2_decrypt_detached
#define VARIANT_mac_init         aegis256x2_mac_init
#define VARIANT_mac_update       aegis256x2_mac_update
#define VARIANT_mac_final        aegis256x2_mac_final
#define VARIANT_mac_verify       aegis256x2_mac_verify

#include "raf_variant.h"
