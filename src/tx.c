#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wally_core.h"
#include "wally_crypto.h"
#include "wally_address.h"
#include "wally_map.h"
#include "wally_script.h"

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

static const char ADDR_FAMILY[] = "bc";

static const uint8_t INTERNAL_PRIVKEY[] = {
    0xa3, 0x4b, 0x99, 0xf2, 0x2c, 0x79, 0x0c, 0x4e,
    0x36, 0xb2, 0xb3, 0xc2, 0xc3, 0x5a, 0x36, 0xdb,
    0x06, 0x22, 0x6e, 0x41, 0xc6, 0x92, 0xfc, 0x82,
    0xb8, 0xb5, 0x6a, 0xc1, 0xc5, 0x40, 0xc5, 0xbd,
};

static const uint8_t INTERNAL_PUBKEY[] = {
    0xa3, 0x4b, 0x99, 0xf2, 0x2c, 0x79, 0x0c, 0x4e,
    0x36, 0xb2, 0xb3, 0xc2, 0xc3, 0x5a, 0x36, 0xdb,
    0x06, 0x22, 0x6e, 0x41, 0xc6, 0x92, 0xfc, 0x82,
    0xb8, 0xb5, 0x6a, 0xc1, 0xc5, 0x40, 0xc5, 0xbd,
};

#define OUTPOINT_TXHASH { \
    0xec, 0x90, 0x16, 0x58, 0x0d, 0x98, 0xa9, 0x39,\
    0x09, 0xfa, 0xf9, 0xd2, 0xf4, 0x31, 0xe7, 0x4f,\
    0x78, 0x1b, 0x43, 0x8d, 0x81, 0x37, 0x2b, 0xb6,\
    0xaa, 0xb4, 0xdb, 0x67, 0x72, 0x5c, 0x11, 0xa7,\
}

const uint32_t OUTPOINT_INDEX = 0;

static const char OUTADDR[] = "bc1qfezv57fvu4z6ew5e6sfsg3sd686nhcuyt8ukve";


static const uint64_t PREV_AMOUNT = 20000UL;
static const uint64_t FEE = 10000UL;
static const uint64_t SENT_AMOUNT = PREV_AMOUNT - FEE;

static void help(const char *cmd)
{
    printf("usage:\n");
    printf("  %s <1 or 2>\n", cmd);
    printf("     1: address\n");
    printf("     2: spent transaction\n");
}

static void dump(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static void tweak_pubkey(
    uint8_t tweakPubKey[EC_XONLY_PUBLIC_KEY_LEN],
    const uint8_t internalPubKey[EC_XONLY_PUBLIC_KEY_LEN]
) {
    int rc;

    uint8_t tweakPubKeyXY[EC_PUBLIC_KEY_LEN];
    rc = wally_ec_public_key_bip341_tweak(
        internalPubKey, EC_XONLY_PUBLIC_KEY_LEN,
        NULL, 0,
        0,
        tweakPubKeyXY, sizeof(tweakPubKeyXY));
    if (rc != WALLY_OK) {
        printf("error: wally_ec_public_key_bip341_tweak fail: %d\n", rc);
        return;
    }
    memcpy(tweakPubKey, tweakPubKeyXY + 1, EC_XONLY_PUBLIC_KEY_LEN);
    printf("tweak pubkey:    ");
    dump(tweakPubKey, EC_XONLY_PUBLIC_KEY_LEN);
}

static void tweak_key_pair(
    uint8_t tweakPrivKey[EC_PRIVATE_KEY_LEN],
    uint8_t tweakPubKey[EC_XONLY_PUBLIC_KEY_LEN],
    const uint8_t internalPrivKey[EC_PRIVATE_KEY_LEN])
{
    int rc;

    uint8_t internalPubKey[EC_PUBLIC_KEY_LEN];
    rc = wally_ec_public_key_from_private_key(
        internalPrivKey, EC_PRIVATE_KEY_LEN,
        internalPubKey, sizeof(internalPubKey));
    if (rc != WALLY_OK) {
        printf("error: wally_ec_public_key_from_private_key fail: %d\n", rc);
        return;
    }
    printf("internal pubkey: ");
    dump(internalPubKey, sizeof(internalPubKey));

    uint8_t tweakPubKeyXY[EC_PUBLIC_KEY_LEN];
    rc = wally_ec_public_key_bip341_tweak(
        internalPubKey, sizeof(internalPubKey),
        NULL, 0,
        0,
        tweakPubKeyXY, sizeof(tweakPubKeyXY));
    if (rc != WALLY_OK) {
        printf("error: wally_ec_public_key_bip341_tweak fail: %d\n", rc);
        return;
    }
    memcpy(tweakPubKey, tweakPubKeyXY + 1, EC_XONLY_PUBLIC_KEY_LEN);
    printf("tweak pubkey:    ");
    dump(tweakPubKey, EC_XONLY_PUBLIC_KEY_LEN);

    rc = wally_ec_private_key_bip341_tweak(
        INTERNAL_PRIVKEY, sizeof(INTERNAL_PRIVKEY),
        NULL, 0,
        0,
        tweakPrivKey, EC_PRIVATE_KEY_LEN);
    if (rc != WALLY_OK) {
        printf("error: wally_ec_private_key_bip341_tweak fail: %d\n", rc);
        return;
    }
    printf("tweak privkey:   ");
    dump(tweakPrivKey, EC_PRIVATE_KEY_LEN);
}

static void address(void)
{
    int rc;

    uint8_t tweakPrivKey[EC_PRIVATE_KEY_LEN];
    uint8_t tweakXonlyPubKey[EC_XONLY_PUBLIC_KEY_LEN];
    tweak_key_pair(tweakPrivKey, tweakXonlyPubKey, INTERNAL_PRIVKEY);

    printf("--------------\n");
    tweak_pubkey(tweakXonlyPubKey, INTERNAL_PUBKEY);
    printf("--------------\n");

    uint8_t witnessProgram[WALLY_WITNESSSCRIPT_MAX_LEN];
    size_t witnessProgramLen = 0;
    rc = wally_witness_program_from_bytes_and_version(
        tweakXonlyPubKey, EC_XONLY_PUBLIC_KEY_LEN,
        1,
        0,
        witnessProgram, sizeof(witnessProgram), &witnessProgramLen);
    if (rc != WALLY_OK) {
        printf("error: wally_witness_program_from_bytes fail: %d\n", rc);
        return;
    }
    printf("witness program: ");
    dump(witnessProgram, witnessProgramLen);

    char *address;
    rc = wally_addr_segwit_from_bytes(
        witnessProgram, witnessProgramLen,
        ADDR_FAMILY,
        0,
        &address);
    if (rc != WALLY_OK) {
        printf("error: wally_addr_segwit_from_bytes fail: %d\n", rc);
        return;
    }
    printf("address: %s\n", address);

    wally_free_string(address);
}

static void spent(void)
{
    int rc;
    struct wally_tx *tx = NULL;

    uint8_t tweakPrivKey[EC_PRIVATE_KEY_LEN];
    uint8_t tweakXonlyPubKey[EC_XONLY_PUBLIC_KEY_LEN];
    tweak_key_pair(tweakPrivKey, tweakXonlyPubKey, INTERNAL_PRIVKEY);

    uint8_t witnessProgram[WALLY_WITNESSSCRIPT_MAX_LEN];
    size_t witnessProgramLen = 0;
    rc = wally_witness_program_from_bytes_and_version(
        tweakXonlyPubKey, EC_XONLY_PUBLIC_KEY_LEN,
        1,
        0,
        witnessProgram, sizeof(witnessProgram), &witnessProgramLen);
    if (rc != WALLY_OK) {
        printf("error: wally_witness_program_from_bytes fail: %d\n", rc);
        return;
    }
    printf("witness program: ");
    dump(witnessProgram, witnessProgramLen);


    // create sigHash, sig and wally_tx
    rc = wally_tx_init_alloc(
        2, // version
        0, // locktime
        1, // vin_cnt
        1, // vout_cnt
        &tx);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_init_alloc fail: %d\n", rc);
        return;
    }

    const struct wally_tx_input TX_INPUT = {
        .txhash = OUTPOINT_TXHASH,
        .index = OUTPOINT_INDEX,
        .sequence = 0xffffffff,
        .script = NULL,
        .script_len = 0,
        .witness = NULL,
        .features = 0,
    };
    rc = wally_tx_add_input(tx, &TX_INPUT);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_add_input fail: %d\n", rc);
        return;
    }

    uint8_t outAddrByte[WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN];
    size_t outAddrLen = 0;
    rc = wally_addr_segwit_to_bytes(
        OUTADDR,
        ADDR_FAMILY,
        0, outAddrByte, sizeof(outAddrByte), &outAddrLen);
    if (rc != WALLY_OK) {
        printf("error: wally_addr_segwit_to_bytes fail: %d\n", rc);
        return;
    }

    const struct wally_tx_output TX_OUTPUT = {
        .satoshi = SENT_AMOUNT,
        .script = outAddrByte,
        .script_len = outAddrLen,
        .features = 0,
    };
    rc = wally_tx_add_output(tx, &TX_OUTPUT);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_add_output fail: %d\n", rc);
        return;
    }

    struct wally_map *scriptPubKey;
    rc = wally_map_init_alloc(1, NULL, &scriptPubKey);
    if (rc != WALLY_OK) {
        printf("error: wally_map_init_alloc fail: %d\n", rc);
        return;
    }
    rc = wally_map_add_integer(
        scriptPubKey,
        0, // key
        witnessProgram, witnessProgramLen);
    if (rc != WALLY_OK) {
        printf("error: wally_map_add_integer fail: %d\n", rc);
        return;
    }

    uint8_t sigHash[EC_MESSAGE_HASH_LEN];
    const uint64_t VALUES[] = { PREV_AMOUNT };
    rc = wally_tx_get_btc_taproot_signature_hash(
        tx,
        0,
        scriptPubKey, // scripts
        VALUES, ARRAY_SIZE(VALUES),
        NULL,  0, // tapleaf
        0x00, // key version
        WALLY_NO_CODESEPARATOR, // codesep position
        NULL, 0, // annex
        WALLY_SIGHASH_ALL,
        0,
        sigHash, sizeof(sigHash)
    );
    wally_map_free(scriptPubKey);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_get_btc_taproot_signature_hash fail: %d\n", rc);
        return;
    }
    printf("sigHash: ");
    dump(sigHash, sizeof(sigHash));

    uint8_t sig[EC_SIGNATURE_LEN + 1];
    rc = wally_ec_sig_from_bytes(
        tweakPrivKey, sizeof(tweakPrivKey),
        sigHash, sizeof(sigHash),
        EC_FLAG_SCHNORR,
        sig, EC_SIGNATURE_LEN
    );
    if (rc != WALLY_OK) {
        printf("error: wally_ec_sig_from_bytes fail: %d\n", rc);
        return;
    }

    sig[EC_SIGNATURE_LEN] = WALLY_SIGHASH_ALL;
    printf("sig: ");
    dump(sig, sizeof(sig));

    struct wally_tx_witness_stack *witness;
    rc = wally_witness_p2tr_from_sig(sig, sizeof(sig), &witness);
    if (rc != WALLY_OK) {
        printf("error: wally_witness_p2tr_from_sig fail: %d\n", rc);
        return;
    }
    rc = wally_tx_set_input_witness(tx, 0, witness);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_set_input_witness fail: %d\n", rc);
        return;
    }
    wally_tx_witness_stack_free(witness);

    uint8_t txData[1024];
    size_t txLen = 0;
    rc = wally_tx_to_bytes(
        tx,
        WALLY_TX_FLAG_USE_WITNESS,
        txData, sizeof(txData), &txLen);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_to_bytes fail: %d\n", rc);
        return;
    }
    printf("hex: ");
    dump(txData, txLen);

    wally_tx_free(tx);
}

int main(int argc, char *argv[])
{
    int rc;

    if (argc != 2 || argv[1][1] != '\0') {
        help(argv[0]);
        return 1;
    }

    rc = wally_init(0);
    if (rc != WALLY_OK) {
        printf("error: wally_init fail: %d\n", rc);
        return 1;
    }

    if (argv[1][0] == '1') {
        address();
    } else if (argv[1][0] == '2') {
        spent();
    } else {
        help(argv[0]);
        return 1;
    }

    rc = wally_cleanup(0);
    if (rc != WALLY_OK) {
        printf("error: wally_cleanup fail: %d\n", rc);
        return 1;
    }
    return 0;
}
