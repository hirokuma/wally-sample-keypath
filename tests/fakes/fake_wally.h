#ifndef FAKE_WALLY_H_
#define FAKE_WALLY_H_

#include "fff.h"

#include <stdio.h>
#include <stddef.h>

#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_map.h>
#include <wally_script.h>

DECLARE_FAKE_VALUE_FUNC(int, bip32_key_from_parent_path_str, const struct ext_key *, const char *, uint32_t, uint32_t, struct ext_key *);
DECLARE_FAKE_VALUE_FUNC(int, bip32_key_from_parent, const struct ext_key *, uint32_t, uint32_t, struct ext_key *);
DECLARE_FAKE_VALUE_FUNC(int, bip32_key_from_seed, const unsigned char *, size_t, uint32_t, uint32_t, struct ext_key *);
DECLARE_FAKE_VALUE_FUNC(int, bip39_mnemonic_from_bytes, const struct words *, const unsigned char *, size_t, char **);
DECLARE_FAKE_VALUE_FUNC(int, bip39_mnemonic_to_seed, const char *, const char *, unsigned char *, size_t, size_t *);
DECLARE_FAKE_VALUE_FUNC(int, bip39_mnemonic_validate, const struct words *, const char *);
DECLARE_FAKE_VALUE_FUNC(void *, wally_malloc, size_t);
DECLARE_FAKE_VALUE_FUNC(int, wally_addr_segwit_from_bytes, const unsigned char *, size_t, const char *, uint32_t, char **);
DECLARE_FAKE_VALUE_FUNC(int, wally_addr_segwit_to_bytes, const char *, const char *, uint32_t, unsigned char *, size_t, size_t *);
DECLARE_FAKE_VALUE_FUNC(int, wally_address_to_scriptpubkey, const char *, uint32_t, unsigned char *, size_t, size_t *);
DECLARE_FAKE_VALUE_FUNC(int, wally_free_string, char *);
DECLARE_FAKE_VALUE_FUNC(int, wally_scriptpubkey_p2tr_from_bytes, const unsigned char *, size_t, uint32_t, unsigned char *, size_t, size_t *);
DECLARE_FAKE_VALUE_FUNC(int, wally_scriptpubkey_get_type, const unsigned char *, size_t, size_t *);
DECLARE_FAKE_VALUE_FUNC(int, wally_scriptpubkey_to_address, const unsigned char *, size_t, uint32_t, char **);
DECLARE_FAKE_VALUE_FUNC(int, wally_ec_private_key_bip341_tweak, const unsigned char *, size_t, const unsigned char *, size_t, uint32_t, unsigned char *, size_t);
DECLARE_FAKE_VALUE_FUNC(int, wally_ec_public_key_bip341_tweak, const unsigned char *, size_t, const unsigned char *, size_t, uint32_t, unsigned char *, size_t);
DECLARE_FAKE_VALUE_FUNC(int, wally_ec_public_key_from_private_key, const unsigned char *, size_t, unsigned char *, size_t);
DECLARE_FAKE_VALUE_FUNC(int, wally_ec_sig_from_bytes, const unsigned char *, size_t, const unsigned char *, size_t, uint32_t, unsigned char *, size_t);
DECLARE_FAKE_VALUE_FUNC(int, wally_map_add_integer, struct wally_map *, uint32_t, const unsigned char *, size_t);
DECLARE_FAKE_VALUE_FUNC(int, wally_map_free, struct wally_map *);
DECLARE_FAKE_VALUE_FUNC(int, wally_map_init_alloc, size_t, wally_map_verify_fn_t, struct wally_map **);
DECLARE_FAKE_VALUE_FUNC(int, wally_tx_add_input, struct wally_tx *, const struct wally_tx_input *);
DECLARE_FAKE_VALUE_FUNC(int, wally_tx_add_output, struct wally_tx *, const struct wally_tx_output *);
DECLARE_FAKE_VALUE_FUNC(int, wally_tx_from_bytes, const unsigned char *, size_t, uint32_t, struct wally_tx **);
DECLARE_FAKE_VALUE_FUNC(int, wally_tx_get_btc_taproot_signature_hash, const struct wally_tx *, size_t, const struct wally_map *, const uint64_t *, size_t, const unsigned char *, size_t, uint32_t, uint32_t, const unsigned char *, size_t, uint32_t, uint32_t, unsigned char *, size_t);
DECLARE_FAKE_VALUE_FUNC(int, wally_tx_get_txid, const struct wally_tx *, unsigned char *, size_t);
DECLARE_FAKE_VALUE_FUNC(int, wally_tx_init_alloc, uint32_t, uint32_t, size_t, size_t, struct wally_tx **);
DECLARE_FAKE_VALUE_FUNC(int, wally_tx_set_input_witness, const struct wally_tx *, size_t, const struct wally_tx_witness_stack *);
DECLARE_FAKE_VALUE_FUNC(int, wally_tx_witness_stack_free, struct wally_tx_witness_stack *);
DECLARE_FAKE_VALUE_FUNC(int, wally_witness_p2tr_from_sig, const unsigned char *, size_t, struct wally_tx_witness_stack **);

#endif /* FAKE_WALLY_H_ */
