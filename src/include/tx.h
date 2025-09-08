#ifndef TX_H_
#define TX_H_

#include <stddef.h>
#include <stdint.h>

#include <wally_transaction.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/////////////////////////////////////////////////
// Prototype definitions
/////////////////////////////////////////////////

/// @brief
/// @param dustlimit
/// @param scriptpubkey
/// @param len
/// @return
int tx_get_dustlimit(uint64_t *dustlimit, const uint8_t *scriptpubkey, size_t len);

/// @brief
/// @param len scriptpubkey length(without script length)
/// @param type WALLY_SCRIPT_TYPE_XXX
/// @return
int tx_get_scriptpubkey_len(size_t *len, size_t type);

/// @brief
/// @param tx
/// @param data
/// @param len
/// @return 0 on success, non-zero on failure.
/// @attention tx wally_tx_free()
int tx_decode(struct wally_tx **tx, const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif /* TX_H_ */
