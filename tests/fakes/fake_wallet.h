#ifndef FAKE_WALLET_H_
#define FAKE_WALLET_H_

#include <stddef.h>
#include <stdint.h>

#include <wally_bip32.h>

#include "fff.h"

#include "wallet.h"

DECLARE_FAKE_VALUE_FUNC(int, wallet_get_address, struct wallet_address *, int *);
DECLARE_FAKE_VALUE_FUNC(int, wallet_init);
DECLARE_FAKE_VALUE_FUNC(int, wallet_new_extr_address, char*);
DECLARE_FAKE_VALUE_FUNC(int, wallet_new_intr_address, char*, uint8_t *, size_t *);
DECLARE_FAKE_VALUE_FUNC(int, wallet_search_scriptpubkey, int *, struct ext_key *, const uint8_t *, size_t);

#endif /* FAKE_WALLET_H_ */
