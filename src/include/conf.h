#ifndef CONF_H_
#define CONF_H_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include <stdint.h>

/////////////////////////////////////////////////
// Macros
/////////////////////////////////////////////////

#define CONF_DISABLE_MAINNET

// wallet
#define PASSPHRASE      ""
#define MNEMONIC_WORDS  (12)
#define WALLET_FILENAME         "mnemonic.wlt"
#define WALLET_INDEX_FILENAME   "index.wlt"

#define DEFAULT_SEQUENCE   (0xfffffffd)

/////////////////////////////////////////////////
// Types
/////////////////////////////////////////////////

enum network_type {
    NETWORK_NONE,
    NETWORK_MAINNET,
    NETWORK_TESTNET3,
    NETWORK_TESTNET4,
    NETWORK_SIGNET,
    NETWORK_REGTEST,
};

struct conf {
    enum network_type network;
    uint32_t wally_network;
    const char *addr_family;
};

/////////////////////////////////////////////////
// Prototype definitions
/////////////////////////////////////////////////

/// @brief Initialize conf from config file.
/// @param config_filename The path to the configuration file.
/// @return 0 on success, non-zero on failure.
int conf_load(const char *config_filename);

/// @brief Get the global conf object.
/// @return A pointer to the global conf struct.
const struct conf *conf_get(void);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif /* CONF_H_ */
