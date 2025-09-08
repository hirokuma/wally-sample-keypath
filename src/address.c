#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_address.h>
#include <wally_script.h>

#include "conf.h"

#include "log.h"
#include "misc.h"
#include "address.h"

/////////////////////////////////////////////////
// prototype definitions
/////////////////////////////////////////////////

static int notsegwit_from_scriptpubkey(char address[ADDRESS_STR_MAX], const uint8_t *scriptpubkey, size_t len);
static int segwit_from_scriptpubkey(char address[ADDRESS_STR_MAX], const uint8_t *scriptpubkey, size_t len);

/////////////////////////////////////////////////
// Public functions
/////////////////////////////////////////////////

int address_from_scriptpubkey(char address[ADDRESS_STR_MAX], const uint8_t *scriptpubkey, size_t len)
{
    int rc;

    size_t type;
    rc = wally_scriptpubkey_get_type(scriptpubkey, len, &type);
    if (rc != WALLY_OK) {
        LOGE("error: wally_scriptpubkey_get_type fail: %d", rc);
        return 1;
    }
    if (type == WALLY_SCRIPT_TYPE_P2WPKH ||
            type == WALLY_SCRIPT_TYPE_P2WSH ||
            type == WALLY_SCRIPT_TYPE_P2TR) {
        return segwit_from_scriptpubkey(address, scriptpubkey, len);
    } else {
        return notsegwit_from_scriptpubkey(address, scriptpubkey, len);
    }
}

int address_to_scriptpubkey(uint8_t scriptpubkey[WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN], size_t *len, const char *address)
{
    int rc;
    const struct conf *conf = conf_get();

    rc = wally_addr_segwit_to_bytes(address, conf->addr_family, 0, scriptpubkey, WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN, len);
    if (rc == WALLY_OK) {
        return 0;
    }

    rc = wally_address_to_scriptpubkey(address, conf->wally_network, scriptpubkey, WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN, len);
    if (rc != WALLY_OK) {
        LOGE("error: wally_addr_segwit_to_bytes and wally_address_to_scriptpubkey fail: %d", rc);
        return 1;
    }
    return 0;
}

/////////////////////////////////////////////////
// Private functions
/////////////////////////////////////////////////

static int notsegwit_from_scriptpubkey(char address[ADDRESS_STR_MAX], const uint8_t *scriptpubkey, size_t len)
{
    int rc;
    char *output;
    const struct conf *conf = conf_get();

    rc = wally_scriptpubkey_to_address(scriptpubkey, len, conf->wally_network, &output);
    if (rc != WALLY_OK) {
        LOGE("error: wally_scriptpubkey_to_address fail: %d", rc);
        return 1;
    }
    snprintf(address, ADDRESS_STR_MAX, "%s", output);
    (void)wally_free_string(output);

    return 0;
}

static int segwit_from_scriptpubkey(char address[ADDRESS_STR_MAX], const uint8_t *scriptpubkey, size_t len)
{
    int rc;
    char *output;
    const struct conf *conf = conf_get();

    rc = wally_addr_segwit_from_bytes(
        scriptpubkey, len,
        conf->addr_family,
        0,
        &output);
    if (rc != WALLY_OK) {
        LOGE("error: wally_witness_program_from_scriptpubkey fail: %d", rc);
        return 1;
    }
    snprintf(address, ADDRESS_STR_MAX, "%s", output);
    (void)wally_free_string(output);

    return 0;
}
