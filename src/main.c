#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_bip32.h>
#include <wally_bip39.h>

#include <secp256k1.h>

#include "misc.h"

#define WALLET_VER      BIP32_VER_TEST_PRIVATE
#define MNEMONIC_LEN    (12)

static int init_random();
static int create_mnemonic(char *mnemonic);
static int create_masterkey(struct ext_key *hdkey, const char *mnemonic);

int main(int argc, char *argv[])
{
    int rc;
    bool have_mnemonic;
    char mnemonic[10 * MNEMONIC_LEN] = "";
    struct ext_key parent_hdkey;

    rc = wally_init(0);
    if (rc != WALLY_OK) {
        fprintf(stderr, "error: wally_init fail: %d\n", rc);
        return 1;
    }

    rc = init_random();
    if (rc != 0) {
        fprintf(stderr, "error: init_random fail: %d\n", rc);
        goto exit;
    }

    have_mnemonic = (argc == 2);
    if (have_mnemonic) {
        if (bip39_mnemonic_validate(NULL, argv[1]) != WALLY_OK) {
            fprintf(stderr, "error: invalid mnemonic\n");
            return 1;
        }
        strcpy(mnemonic, argv[1]);
    }

    if (!have_mnemonic) {
        create_mnemonic(mnemonic);
        printf("mnimonic: \"%s\"\n", mnemonic);
    }

    rc = create_masterkey(&parent_hdkey, mnemonic);
    if (rc != 0) {
        fprintf(stderr, "error: create_bip32key fail: %d\n", rc);
        goto exit;
    }

    struct ext_key child_hdkey;
    // m / purpose' / coin_type' / account' / change / address_index
    // purpose = 44, 49, 84
    // coin_type = 0(mainnet), 1(testnet)
    rc = bip32_key_from_parent_path_str(&parent_hdkey, "m/86'/1'/0'/0/0", 0, 0, &child_hdkey);
    if (rc != WALLY_OK) {
        fprintf(stderr, "error: bip32_key_from_parent_path_str fail: %d\n", rc);
        goto exit;
    }


exit:
    wally_cleanup(0);
    return 0;
}

static int init_random()
{
    int rc;
    uint8_t ent[BIP39_ENTROPY_LEN_256];
    rc = fill_random(ent, sizeof(ent));
    if (rc != 0) {
        fprintf(stderr, "error: fill_random fail: %d\n", rc);
        return 1;
    }
    rc = wally_secp_randomize(ent, sizeof(ent));
    if (rc != WALLY_OK) {
        fprintf(stderr, "error: wally_secp_randomize fail: %d\n", rc);
        return 1;
    }

    return 0;
}

static int create_mnemonic(char *mnemonic)
{
    int rc;
    uint8_t r[MNEMONIC_LEN * 2];    // r[i] | r[i+1] << 8

    rc = fill_random(r, sizeof(r));
    if (rc != 0) {
        fprintf(stderr, "error: fill_random fail: %d\n", rc);
        return 1;
    }

    // このAPIの方がよい？
    // char *mm;
    // bip39_mnemonic_from_bytes(NULL, r, sizeof(r), &mm);
    // printf("mm: %s\n", mm);
    // wally_free_string(mm);

    for (int i = 0; i < sizeof(r) / 2; i++) {
        int rnd = (r[2 * i] | ((uint16_t)r[2 * i + 1]) << 8) % BIP39_WORDLIST_LEN;
        strcat(mnemonic, bip39_get_word_by_index(NULL, rnd));
        strcat(mnemonic, " ");
    }
    mnemonic[strlen(mnemonic) - 1] = '\0';
    return 0;
}

static int create_masterkey(struct ext_key *hdkey, const char *mnemonic)
{
    int rc;

    uint8_t seed[BIP39_SEED_LEN_512];
    size_t written;
    rc = bip39_mnemonic_to_seed(mnemonic, "", seed, sizeof(seed), &written);
    if (rc != WALLY_OK || written != BIP39_SEED_LEN_512) {
        fprintf(stderr, "error: bip39_mnemonic_to_seed fail: %d(written=%ld)\n", rc, written);
        return 1;
    }
    // printf("seed: ");
    // dump(seed, sizeof(seed));

    rc = bip32_key_from_seed(seed, sizeof(seed), WALLET_VER, 0, hdkey);
    if (rc != WALLY_OK) {
        fprintf(stderr, "error: bip32_key_from_seed fail: %d\n", rc);
        return 1;
    }

    return 0;
}
