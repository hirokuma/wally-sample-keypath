#include "fff.h"
#include "fakes.h"

DEFINE_FAKE_VOID_FUNC(dump, const uint8_t *, size_t);
DEFINE_FAKE_VOID_FUNC(dump_rev, const uint8_t *, size_t);
DEFINE_FAKE_VALUE_FUNC(int, fill_random, uint8_t *, size_t);
DEFINE_FAKE_VOID_FUNC(txhash_to_txid_string, char*, const uint8_t*);
