#ifndef ADDRESS_H_
#define ADDRESS_H_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include <stddef.h>
#include <stdint.h>

#include <wally_address.h>

/////////////////////////////////////////////////
// Macros
/////////////////////////////////////////////////

// Bech32m addresses can be up to 90 characters long. Add 1 for null terminator.
#define ADDRESS_STR_MAX (91)

/////////////////////////////////////////////////
// Prototype definitions
/////////////////////////////////////////////////

/// @brief Retrieve Bitcoin address from scriptPubKey
/// @param address
/// @param scriptpubkey
/// @param len
/// @return
int address_from_scriptpubkey(char address[ADDRESS_STR_MAX], const uint8_t *scriptpubkey, size_t len);

/// @brief
/// @param scriptpubkey
/// @param len
/// @param address
/// @return
int address_to_scriptpubkey(uint8_t scriptpubkey[WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN], size_t *len, const char *address);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif /* ADDRESS_H_ */
