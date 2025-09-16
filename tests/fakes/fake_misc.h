#ifndef FAKE_MISC_H_
#define FAKE_MISC_H_

#include <stddef.h>
#include <stdint.h>

#include "fff.h"

#include "misc.h"

DECLARE_FAKE_VOID_FUNC(dump, const uint8_t *, size_t);
DECLARE_FAKE_VOID_FUNC(dump_rev, const uint8_t *, size_t);
DECLARE_FAKE_VALUE_FUNC(int, fill_random, uint8_t *, size_t);
DECLARE_FAKE_VOID_FUNC(txhash_to_txid_string, char*, const uint8_t*);

#endif /* FAKE_MISC_H_ */
