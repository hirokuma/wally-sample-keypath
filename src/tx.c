#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_address.h>
#include <wally_map.h>
#include <wally_script.h>

#include "log.h"
#include "misc.h"
#include "tx.h"

/////////////////////////////////////////////////
// Prototype definitions
/////////////////////////////////////////////////

static int decode_raw(struct wally_tx **tx, const uint8_t *data, size_t len);

/////////////////////////////////////////////////
// Public functions
/////////////////////////////////////////////////

int tx_get_dustlimit(uint64_t *dustlimit, const uint8_t *scriptpubkey, size_t len)
{
    int rc;

    size_t type;
    rc = wally_scriptpubkey_get_type(scriptpubkey, len, &type);
    if (rc != WALLY_OK) {
        LOGE("error: wally_scriptpubkey_get_type fail: %d", rc);
        return 1;
    }
    // https://github.com/lightning/bolts/issues/905
    // https://chatgpt.com/share/68bb6fd5-afac-8001-aa9e-aca051311b8e
    switch (type) {
        case WALLY_SCRIPT_TYPE_P2PKH:
            *dustlimit = 546;
            break;
        case WALLY_SCRIPT_TYPE_P2SH:
            *dustlimit = 540;
            break;
        case WALLY_SCRIPT_TYPE_P2WPKH:
            *dustlimit = 294;
            break;
        case WALLY_SCRIPT_TYPE_P2WSH:
        case WALLY_SCRIPT_TYPE_P2TR:
            *dustlimit = 330;
            break;
        default:
            LOGE("error: unknown script type: %d", (int)type);
            return 1;
    }
    return 0;
}

int tx_get_scriptpubkey_len(size_t *len, size_t type)
{
    switch (type) {
        case WALLY_SCRIPT_TYPE_P2PKH:
            *len = 25;
            break;
        case WALLY_SCRIPT_TYPE_P2SH:
            *len = 23;
            break;
        case WALLY_SCRIPT_TYPE_P2WPKH:
            *len = 22;
            break;
        case WALLY_SCRIPT_TYPE_P2WSH:
        case WALLY_SCRIPT_TYPE_P2TR:
            *len = 34;
            break;
        default:
            LOGE("error: unknown script type: %d", (int)type);
            return 1;
    }
    return 0;
}

int tx_decode(struct wally_tx **tx, const uint8_t *data, size_t len)
{
    int rc;

    rc = decode_raw(tx, data, len);
    if (rc != 0) {
        LOGE("error: decode_raw fail: %d", rc);
        return 1;
    }
    return 0;
}

/////////////////////////////////////////////////
// Private functions
/////////////////////////////////////////////////

static int decode_raw(struct wally_tx **tx, const uint8_t *data, size_t len)
{
    int rc;
    const uint32_t flags[] = { WALLY_TX_FLAG_USE_WITNESS, 0 };

    for (size_t i = 0; i < ARRAY_SIZE(flags); i++) {
        rc = wally_tx_from_bytes(data, len, flags[i], tx);
        if (rc == WALLY_OK) {
            return 0;
        }
    }
    return 1;
}
