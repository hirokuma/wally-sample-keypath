#include <stdio.h>
#include <stdlib.h>

#include <sys/random.h>

#include "misc.h"

void dump(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void dump_rev(const uint8_t *data, size_t len)
{
    if (len == 0) {
        return;
    }
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[len - i - 1]);
    }
    printf("\n");
}

// https://github.com/bitcoin-core/secp256k1/blob/master/examples/examples_util.h
int fill_random(uint8_t *data, size_t len)
{
    ssize_t res = getrandom(data, len, 0);
    return !((size_t)res == len);
}

void txhash_to_txid_string(char txid[TX_TXID_STR_MAX], const uint8_t txhash[WALLY_TXHASH_LEN])
{
    for (int i = 0; i < WALLY_TXHASH_LEN; i++) {
        sprintf(txid + i * 2, "%02x", txhash[WALLY_TXHASH_LEN - i - 1]);
    }
    txid[64] = '\0';
}
