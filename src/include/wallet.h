#ifndef WALLET_H_
#define WALLET_H_

#include <stdint.h>
#include <stddef.h>

#include <wally_bip32.h>

#include "address.h"


#ifdef __cplusplus
extern "C" {
#endif

/////////////////////////////////////////////////
// Macros
/////////////////////////////////////////////////

#define WALLET_KEYS_EXTN    0
#define WALLET_KEYS_INTR    1
#define WALLET_KEYS_NUM     2

/////////////////////////////////////////////////
// Types
/////////////////////////////////////////////////

struct wallet_address {
    char address[ADDRESS_STR_MAX];
    int32_t keys_type; // WALLET_KEYS_EXTN or WALLET_KEYS_INTR
    uint32_t index;
};
#define WALLET_GET_ADDR_INIT    { .keys_type = WALLET_KEYS_EXTN, .index = 0 }

/////////////////////////////////////////////////
// Prototype definitions
/////////////////////////////////////////////////

/// @brief Initialize wallet.
/// @return 0 on success, non-zero on failure.
int wallet_init(void);

/// @brief
/// @param wa
/// @param done
/// @return 0 on success, non-zero on failure.
int wallet_get_address(struct wallet_address *wa, int *done);

/// @brief Retrieve an external wallet address.
/// @param address A buffer that will be populated with the external wallet address.
/// @return 0 on success, non-zero on failure.
int wallet_new_extr_address(char address[ADDRESS_STR_MAX]);

/// @brief Retrieve an internal wallet address.
/// @param address A buffer that will be populated with the internal wallet address.
/// @return 0 on success, non-zero on failure.
int wallet_new_intr_address(char address[ADDRESS_STR_MAX]);

int wallet_search_scriptpubkey(int *detect, struct ext_key *hdkey, const uint8_t *scriptpubkey, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* WALLET_H_ */
