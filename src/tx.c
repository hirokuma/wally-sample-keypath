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
