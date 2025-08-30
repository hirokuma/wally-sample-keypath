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

// https://github.com/bitcoin-core/secp256k1/blob/master/examples/examples_util.h
int fill_random(uint8_t *data, size_t len)
{
    ssize_t res = getrandom(data, len, 0);
    return !((size_t)res == len);
}
