#include <stddef.h>
#include <stdint.h>

#include "raf_internal.h"

#include "../include/aegis128l.h"

#define VARIANT   aegis128l
#define KEYBYTES  aegis128l_KEYBYTES
#define NPUBBYTES aegis128l_NPUBBYTES
#define ALG_ID    AEGIS_RAF_ALG_128L

#define VARIANT_encrypt_detached aegis128l_encrypt_detached
#define VARIANT_decrypt_detached aegis128l_decrypt_detached
#define VARIANT_mac_init         aegis128l_mac_init
#define VARIANT_mac_update       aegis128l_mac_update
#define VARIANT_mac_final        aegis128l_mac_final
#define VARIANT_mac_verify       aegis128l_mac_verify

#include "raf_variant.h"
