#ifndef TX_H_
#define TX_H_

#include <stddef.h>
#include <stdint.h>

#include <wally_transaction.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/////////////////////////////////////////////////
// Types
/////////////////////////////////////////////////

// TODO 名前が...
struct tx_spend_1in_1out {
    struct wally_tx *input_tx;
    uint32_t out_index;
    uint8_t *out_scriptpubkey;
    size_t out_scriptpubkey_len;
    uint64_t amount;
    double feerate;
};

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

/// @brief
/// @param tx
/// @return
int tx_show_detail(const struct wally_tx *tx);


int tx_create_spend_1in_1out(struct wally_tx **tx, const struct tx_spend_1in_1out *param);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif /* TX_H_ */
