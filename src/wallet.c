#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_script.h>

#include "conf.h"

#include "address.h"
#include "log.h"
#include "misc.h"
#include "wallet.h"

/////////////////////////////////////////////////
// Macros
/////////////////////////////////////////////////

// m / purpose' / coin_type' / account' / change / address_index
// purpose = 44(P2PKH), 49(P2WPKH-nested-in-BIP16), 84(P2WPKH), 86(P2TR)
// coin_type = 0(mainnet), 1(testnet)
#define WALLET_PATH     "m/86'/1'/0'/*" // P2TR only

#if MNEMONIC_WORDS == 12
#   define  ENTROPY_LEN    (BIP39_ENTROPY_LEN_128)
#elif MNEMONIC_WORDS == 24
#   define  ENTROPY_LEN    (BIP39_ENTROPY_LEN_256)
#else
#   error "invalid MNEMONIC_WORDS"
#endif

#define MNEMONIC_STR_MAX    (MNEMONIC_WORDS * 10)

/////////////////////////////////////////////////
// Types
/////////////////////////////////////////////////

struct wallet_set {
    struct ext_key hdkey;
    uint32_t next_index;
};

struct wallet_data {
    struct wallet_set ws[WALLET_KEYS_NUM];
};

/////////////////////////////////////////////////
// Global variables
/////////////////////////////////////////////////

static struct wallet_data opened_wallet;

/////////////////////////////////////////////////
// Prototype definitions
/////////////////////////////////////////////////

static int load_wallet(char **mnemonic, struct wallet_data *wd);
static int load_mnemonic_file(char **mnemonic);
static int load_index_file(struct wallet_data *wd);
static int create_wallet(char **mnemonic, struct wallet_data *wd);
static int create_mnemonic_file(char **mnemonic);
static int save_index_file(struct wallet_data *wd);
static int create_masterkey(struct ext_key *hdkey, const char *mnemonic);
static int new_address(char address[ADDRESS_STR_MAX], struct wallet_set *ws, uint8_t *scriptpubkey, size_t *len);
static int get_addr_hdkey(struct ext_key *hdkey, const struct ext_key *chg_hdkey, uint32_t index);
static int get_address(char address[ADDRESS_STR_MAX], struct ext_key *addr_hdkey, uint8_t *scriptpubkey, size_t *len);
static int get_scriptpubkey_from_hdkey(uint8_t *scriptpubkey, size_t *len, const struct ext_key *addr_hdkey);

/////////////////////////////////////////////////
// Public functions
/////////////////////////////////////////////////

int wallet_init(void)
{
    int rc;
    char *mnemonic;
    struct ext_key parent_hdkey;
    int rc_stat;
    struct stat st;

    rc_stat = stat(WALLET_FILENAME, &st);
    if (rc_stat == 0) {
        rc = load_wallet(&mnemonic, &opened_wallet);
    } else {
        rc = create_wallet(&mnemonic, &opened_wallet);
    }
    if (rc != 0) {
        LOGE("error: create or load wallet fail: %d", rc);
        return 1;
    }

    rc = create_masterkey(&parent_hdkey, mnemonic);
    (void)wally_free_string(mnemonic); // clear and free
    if (rc != 0) {
        LOGE("error: create_bip32key fail: %d", rc);
        return 1;
    }

    rc = bip32_key_from_parent_path_str(
        &parent_hdkey,
        WALLET_PATH, 0,
        BIP32_FLAG_STR_WILDCARD,
        &opened_wallet.ws[WALLET_KEYS_EXTN].hdkey);
    if (rc != WALLY_OK) {
        LOGE("error: bip32_key_from_parent_path_str(extn) fail: %d", rc);
        return 1;
    }

    rc = bip32_key_from_parent_path_str(
        &parent_hdkey,
        WALLET_PATH, 1,
        BIP32_FLAG_STR_WILDCARD,
        &opened_wallet.ws[WALLET_KEYS_INTR].hdkey);
    if (rc != WALLY_OK) {
        LOGE("error: bip32_key_from_parent_path_str(intr) fail: %d", rc);
        return 1;
    }

    return 0;
}

int wallet_get_address(struct wallet_address *wa, int *done)
{
    int rc;

    *done = 0;
    if (wa->keys_type == WALLET_KEYS_EXTN) {
        if (wa->index == opened_wallet.ws[WALLET_KEYS_EXTN].next_index) {
            LOGT("to intr address");
            wa->keys_type = WALLET_KEYS_INTR;
            wa->index = 0;
        }
    }
    if (wa->keys_type == WALLET_KEYS_INTR) {
        if (wa->index == opened_wallet.ws[WALLET_KEYS_INTR].next_index) {
            LOGT("done");
            *done = 1;
            return 0;
        }
    }

    struct ext_key addr_hdkey;
    rc = get_addr_hdkey(&addr_hdkey, &opened_wallet.ws[wa->keys_type].hdkey, wa->index);
    if (rc != 0) {
        LOGE("error: get_addr_hdkey fail: %d", rc);
        return 1;
    }
    rc = get_address(wa->address, &addr_hdkey, NULL, 0);
    if (rc == 0) {
        wa->index++;
    }
    return rc;
}

int wallet_new_extr_address(char address[ADDRESS_STR_MAX])
{
    return new_address(address, &opened_wallet.ws[WALLET_KEYS_EXTN], NULL, 0);
}

int wallet_new_intr_address(char address[ADDRESS_STR_MAX], uint8_t *scriptpubkey, size_t *len)
{
    return new_address(address, &opened_wallet.ws[WALLET_KEYS_INTR], scriptpubkey, len);
}

// TODO 今のところP2TR専用
int wallet_search_scriptpubkey(int *detect, struct ext_key *hdkey, const uint8_t *scriptpubkey, size_t len)
{
    int rc;
    uint8_t spk[WALLY_SCRIPTPUBKEY_P2TR_LEN];
    struct ext_key addr_hdkey;

    *detect = 0;
    if (len != WALLY_SCRIPTPUBKEY_P2TR_LEN) {
        LOGT("not same length");
        return 1;
    }

    for (int chgkey_index = 0; chgkey_index < WALLET_KEYS_NUM; chgkey_index++) {
        struct wallet_set *ws = &opened_wallet.ws[chgkey_index];
        if (ws->next_index > 0) {
            for (uint32_t index = 0; index < ws->next_index; index++) {
                rc = get_addr_hdkey(&addr_hdkey, &ws->hdkey, index);
                if (rc != 0) {
                    LOGE("error: get_addr_hdkey fail: %d", rc);
                    return 1;
                }
                size_t written = sizeof(spk);
                rc = get_scriptpubkey_from_hdkey(spk, &written, &addr_hdkey);
                if (rc != WALLY_OK) {
                    LOGE("error: get_scriptpubkey_from_hdkey fail: %d", rc);
                    return 1;
                }
                if (memcmp(spk, scriptpubkey, len) == 0) {
                    LOGT("detect!");
                    *detect = 1;
                    if (hdkey != NULL) {
                        memcpy(hdkey, &addr_hdkey, sizeof(struct ext_key));
                    }
                    return 0;
                }
            }
        }
    }
    LOGT("not match");
    return 0;
}

/////////////////////////////////////////////////
// Private functions
/////////////////////////////////////////////////

static int load_wallet(char **mnemonic, struct wallet_data *wd)
{
    int rc;

    char *m;
    rc = load_mnemonic_file(&m);
    if (rc != 0) {
        LOGE("error: load_mnemonic_file fail: %d", rc);
        goto exit;
    }

    rc = load_index_file(wd);
    if (rc != 0) {
        LOGE("error: load_index_file fail: %d", rc);
        goto exit;
    }

    *mnemonic = m;
    return 0;

exit:
    if (m) {
        (void)wally_free_string(m); // clear and free
    }
    return 1;
}

static int load_mnemonic_file(char **mnemonic)
{
    int rc;
    char *wp; // work pointer

    char *m = (char *)wally_malloc(MNEMONIC_STR_MAX);
    if (!m) {
        LOGE("error: wally_malloc failed");
        return 1;
    }

    FILE *fp = fopen(WALLET_FILENAME, "r");
    if (fp == NULL) {
        LOGE("error: fopen for reading failed");
        goto exit;
    }
    wp = fgets(m, MNEMONIC_STR_MAX, fp);
    fclose(fp);
    if (wp == NULL) {
        LOGE("error: fgets failed");
        goto exit;
    }
    wp = strchr(m, '\n');
    if (wp) {
        *wp = '\0';
    }

    rc = bip39_mnemonic_validate(NULL, m);
    if (rc != WALLY_OK) {
        LOGE("error: invalid mnemonic(%s)", m);
        goto exit;
    }

    *mnemonic = m;
    return 0;

exit:
    if (m) {
        (void)wally_free_string(m); // clear and free
    }
    return 1;
}

static int load_index_file(struct wallet_data *wd)
{
    int rc;
    uint32_t next_extn, next_intr;

    FILE *fp = fopen(WALLET_INDEX_FILENAME, "r");
    if (fp == NULL) {
        LOGE("error: fopen for reading failed");
        return 1;
    }
    rc = fscanf(fp, "%u %u", &next_extn, &next_intr);
    fclose(fp);

    if (rc != 2) {
        LOGE("error: fscanf failed");
        return 1;
    }

    wd->ws[WALLET_KEYS_EXTN].next_index = next_extn;
    wd->ws[WALLET_KEYS_INTR].next_index = next_intr;
    return 0;
}

static int create_wallet(char **mnemonic, struct wallet_data *wd)
{
    int rc;

    rc = create_mnemonic_file(mnemonic);
    if (rc != 0) {
        LOGE("error: create_mnemonic_file fail: %d", rc);
        return rc;
    }

    wd->ws[WALLET_KEYS_EXTN].next_index = 0;
    wd->ws[WALLET_KEYS_INTR].next_index = 0;
    rc = save_index_file(wd);
    if (rc != 0) {
        LOGE("error: save_index_file fail: %d", rc);
        return rc;
    }

    return 0;
}

static int create_mnemonic_file(char **mnemonic)
{
    int rc;
    uint8_t ent[ENTROPY_LEN];

    rc = fill_random(ent, sizeof(ent));
    if (rc != 0) {
        LOGE("error: fill_random fail: %d", rc);
        return 1;
    }

    char *m;
    rc = bip39_mnemonic_from_bytes(NULL, ent, sizeof(ent), &m);
    if (rc != WALLY_OK) {
        LOGE("error: bip39_mnemonic_from_bytes fail: %d", rc);
        return 1;
    }

    // Dangerous!! Only test!!
    FILE *fp = fopen(WALLET_FILENAME, "w");
    if (fp == NULL) {
        LOGE("error: fopen for writing failed");
        goto exit;
    }
    fprintf(fp, "%s\n# %s", m, WALLET_PATH);
    fclose(fp);

    *mnemonic = m;
    return 0;

exit:
    if (m) {
        (void)wally_free_string(m); // clear and free
    }
    return 1;
}

static int save_index_file(struct wallet_data *wd)
{
    FILE *fp = fopen(WALLET_INDEX_FILENAME, "w");
    if (fp == NULL) {
        LOGE("error: fopen for writing failed");
        return 1;
    }
    fprintf(fp, "%u %u", wd->ws[WALLET_KEYS_EXTN].next_index, wd->ws[WALLET_KEYS_INTR].next_index);
    fclose(fp);

    return 0;
}

static int create_masterkey(struct ext_key *hdkey, const char *mnemonic)
{
    int rc;
    const struct conf *conf = conf_get();

    uint8_t seed[BIP39_SEED_LEN_512];
    size_t written;
    rc = bip39_mnemonic_to_seed(mnemonic, PASSPHRASE, seed, sizeof(seed), &written);
    if (rc != WALLY_OK || written != BIP39_SEED_LEN_512) {
        LOGE("error: bip39_mnemonic_to_seed fail: %d(written=%zu)", rc, written);
        return 1;
    }

    uint32_t wallet_version;
    if (conf->network == NETWORK_MAINNET) {
        wallet_version = BIP32_VER_MAIN_PRIVATE;
    } else {
        wallet_version = BIP32_VER_TEST_PRIVATE;
    }
    rc = bip32_key_from_seed(seed, sizeof(seed), wallet_version, 0, hdkey);
    if (rc != WALLY_OK) {
        LOGE("error: bip32_key_from_seed fail: %d", rc);
        return 1;
    }

    return 0;
}

static int new_address(char address[ADDRESS_STR_MAX], struct wallet_set *ws, uint8_t *scriptpubkey, size_t *len)
{
    int rc;
    struct ext_key addr_hdkey;

    rc = get_addr_hdkey(&addr_hdkey, &ws->hdkey, ws->next_index);
    if (rc != 0) {
        LOGE("error: get_addr_hdkey fail: %d", rc);
        return 1;
    }

    rc = get_address(address, &addr_hdkey, scriptpubkey, len);
    if (rc != 0) {
        LOGE("error: get_address fail: %d", rc);
        return 1;
    }

    ws->next_index++;
    rc = save_index_file(&opened_wallet);
    if (rc != 0) {
        LOGE("error: save_index_file fail: %d", rc);
        return 1;
    }

    return 0;
}

static int get_addr_hdkey(struct ext_key *hdkey, const struct ext_key *chg_hdkey, uint32_t index)
{
    int rc;

    if (chg_hdkey->depth != 4) {
        LOGE("addr_hdkey.depth is not 4");
        return 1;
    }

    rc = bip32_key_from_parent(chg_hdkey, index, BIP32_FLAG_KEY_PRIVATE, hdkey);
    if (rc != WALLY_OK) {
        LOGE("error: bip32_key_from_parent fail: %d", rc);
        return 1;
    }
    if (hdkey->priv_key[0] != BIP32_FLAG_KEY_PRIVATE) {
        LOGE("err: hdkey.priv_key[0] != BIP32_FLAG_KEY_PRIVATE");
        return 1;
    }

    return 0;
}

static int get_address(char address[ADDRESS_STR_MAX], struct ext_key *addr_hdkey, uint8_t *scriptpubkey, size_t *len)
{
    int rc;

    if (addr_hdkey->depth != 5) {
        LOGE("addr_hdkey.depth is not 5");
        return 1;
    }

    uint8_t spk[WALLY_SCRIPTPUBKEY_P2TR_LEN];
    size_t written = sizeof(spk);
    rc = get_scriptpubkey_from_hdkey(spk, &written, addr_hdkey);
    if (rc != 0 || written != WALLY_SCRIPTPUBKEY_P2TR_LEN) { // TODO P2TR only
        LOGE("error: get_scriptpubkey_from_hdkey fail: %d", rc);
        return 1;
    }

    rc = address_from_scriptpubkey(address, spk, written);
    if (rc != 0) {
        LOGE("error: address_from_scriptpubkey fail: %d", rc);
        return 1;
    }

    if (scriptpubkey != NULL && len != NULL) {
        if (*len < written) {
            LOGE("error: scriptpubkey is too short");
            return 1;
        }
        memcpy(scriptpubkey, spk, written);
        *len = written;
    }

    return 0;
}

// TODO P2TR only
static int get_scriptpubkey_from_hdkey(uint8_t *scriptpubkey, size_t *len, const struct ext_key *addr_hdkey)
{
    int rc;
    const uint8_t *pubkey = addr_hdkey->pub_key;

    if (addr_hdkey->depth != 5) {
        LOGE("addr_hdkey.depth is not 5");
        return 1;
    }

    size_t written;
    rc = wally_scriptpubkey_p2tr_from_bytes(
        pubkey, EC_PUBLIC_KEY_LEN,
        0, scriptpubkey, *len, &written);
    if (rc != WALLY_OK || written > *len) {
        LOGE("error: wally_scriptpubkey_p2tr_from_bytes fail: %d", rc);
        return 1;
    }
    *len = written;

    return 0;
}
