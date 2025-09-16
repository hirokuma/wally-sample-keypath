#include "fff.h"
#include "fakes.h"

DEFINE_FAKE_VALUE_FUNC(int, wallet_get_address, struct wallet_address *, int *);
DEFINE_FAKE_VALUE_FUNC(int, wallet_init);
DEFINE_FAKE_VALUE_FUNC(int, wallet_new_extr_address, char*);
DEFINE_FAKE_VALUE_FUNC(int, wallet_new_intr_address, char*, uint8_t *, size_t *);
DEFINE_FAKE_VALUE_FUNC(int, wallet_search_scriptpubkey, int *, struct ext_key *, const uint8_t *, size_t);
