#ifndef FAKE_TX_H_
#define FAKE_TX_H_

#include <stddef.h>
#include <stdint.h>

#include <wally_transaction.h>

#include "fff.h"

#include "tx.h"

DECLARE_FAKE_VALUE_FUNC(int, tx_create_spend_1in_1out, struct wally_tx **, const struct tx_spend_1in_1out *);
DECLARE_FAKE_VALUE_FUNC(int, tx_decode, struct wally_tx **, const uint8_t *, size_t);
DECLARE_FAKE_VALUE_FUNC(int, tx_get_dustlimit, uint64_t *, const uint8_t *, size_t);
DECLARE_FAKE_VALUE_FUNC(int, tx_get_scriptpubkey_len, size_t *, size_t);
DECLARE_FAKE_VALUE_FUNC(int, tx_show_detail, const struct wally_tx *);

#endif /* FAKE_TX_H_ */
