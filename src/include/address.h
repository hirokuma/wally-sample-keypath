#ifndef ADDRESS_H_
#define ADDRESS_H_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include <stddef.h>
#include <stdint.h>

/////////////////////////////////////////////////
// Macros
/////////////////////////////////////////////////

// Bech32m addresses can be up to 90 characters long. Add 1 for null terminator.
#define ADDRESS_STR_MAX (91)

/////////////////////////////////////////////////
// Prototype definitions
/////////////////////////////////////////////////

/// @brief
/// @param dustlimit
/// @param scriptpubkey
/// @param len
/// @return
int address_get_dustlimit(uint64_t *dustlimit, const uint8_t *scriptpubkey, size_t len);

/// @brief Retrieve Bitcoin address from scriptPubKey
/// @param address
/// @param scriptpubkey
/// @param len
/// @return
int address_from_scriptpubkey(char address[ADDRESS_STR_MAX], const uint8_t *scriptpubkey, size_t len);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif /* ADDRESS_H_ */
