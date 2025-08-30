#ifndef MISC_H_
#define MISC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include <wally_transaction.h>

/////////////////////////////////////////////////
// Macros
/////////////////////////////////////////////////

/// @brief Array size
#define ARRAY_SIZE(a)       (sizeof(a) / sizeof(a[0]))

/// @brief Struct member size
#define MEMBER_SIZE(a, m)   (sizeof(((a *)NULL)->m))

#define TX_TXID_STR_MAX (WALLY_TXHASH_LEN * 2 + 1)

/////////////////////////////////////////////////
// Prototype definitions
/////////////////////////////////////////////////

/// @brief Dump hex string to stdout.
/// @param data
/// @param len
void dump(const uint8_t *data, size_t len);

/// @brief Dump reversed hex string to stdout.
/// @param data
/// @param len
void dump_rev(const uint8_t *data, size_t len);

/// @brief Fill the given buffer with cryptographically secure random bytes.
/// @param data The buffer that will be filled with random data.
/// @param len data length
/// @return 0 on success, non-zero on failure.
int fill_random(uint8_t *data, size_t len);

/// @brief
/// @param txid
/// @param txhash
void txhash_to_txid_string(char txid[TX_TXID_STR_MAX], const uint8_t txhash[WALLY_TXHASH_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* MISC_H_ */
