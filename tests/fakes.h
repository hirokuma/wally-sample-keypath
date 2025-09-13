#ifndef FAKES_H_
#define FAKES_H_

#include "fff/fff.h"

#include <stdio.h>
#include <stddef.h>

#include <sys/stat.h>

#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_script.h>

#ifdef UNIT_TEST

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
DECLARE_FAKE_VALUE_FUNC(int, stat, const char *, struct stat *);

#endif // UNIT_TEST

#endif /* FAKES_H_ */
