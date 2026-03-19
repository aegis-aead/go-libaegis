#include <stddef.h>
#include <stdint.h>

#include "raf_internal.h"

#include "../include/aegis128x2.h"

#define VARIANT   aegis128x2
#define KEYBYTES  aegis128x2_KEYBYTES
#define NPUBBYTES aegis128x2_NPUBBYTES
#define ALG_ID    AEGIS_RAF_ALG_128X2

#define VARIANT_encrypt_detached aegis128x2_encrypt_detached
#define VARIANT_decrypt_detached aegis128x2_decrypt_detached
#define VARIANT_mac_init         aegis128x2_mac_init
#define VARIANT_mac_update       aegis128x2_mac_update
#define VARIANT_mac_final        aegis128x2_mac_final
#define VARIANT_mac_verify       aegis128x2_mac_verify

#include "raf_variant.h"
