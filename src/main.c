#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <errno.h>

#include <wally_address.h>
#include <wally_bip39.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_map.h>
#include <wally_script.h>

#include "conf.h"

#include "address.h"
#include "log.h"
#include "misc.h"
#include "tx.h"
#include "wallet.h"

/////////////////////////////////////////////////
// Macros
/////////////////////////////////////////////////

#define CONFIG_FILENAME "settings.conf"

/////////////////////////////////////////////////
// Prototype definitions
/////////////////////////////////////////////////

static int init(void);
static int cmd_help(int argc, char *argv[]);
static int cmd_addresses(int argc, char *argv[]);
static int cmd_newaddress(int argc, char *argv[]);
static int cmd_tx(int argc, char *argv[]);
static int cmd_spend(int argc, char *argv[]);


int main(int argc, char *argv[])
{
    int rc;
    rc = conf_load(CONFIG_FILENAME);
    if (rc != 0) {
        fprintf(stderr, "error: settings_init fail: %d(%s)\n", rc, CONFIG_FILENAME);
        goto exit;
    }

    rc = init();
    if (rc != 0) {
        fprintf(stderr, "error: init fail: %d\n", rc);
        goto exit;
    }

    LOGT("wallet_init");
    rc = wallet_init();
    if (rc != 0) {
        fprintf(stderr, "error: wallet_init fail: %d\n", rc);
        goto exit;
    }

    if (argc <= 1 || strcmp(argv[1], "help") == 0) {
        LOGT("cmd_help");
        rc = cmd_help(argc, argv);
    } else if (strcmp(argv[1], "addr") == 0) {
        LOGT("cmd_address");
        rc = cmd_addresses(argc, argv);
    } else if (strcmp(argv[1], "newaddr") == 0) {
        LOGT("cmd_newaddress");
        rc = cmd_newaddress(argc, argv);
    } else if (strcmp(argv[1], "tx") == 0) {
        LOGT("cmd_tx");
        rc = cmd_tx(argc, argv);
    } else if (strcmp(argv[1], "spend") == 0) {
        LOGT("cmd_spend");
        rc = cmd_spend(argc, argv);
    } else {
        fprintf(stderr, "invalid option: %s\n", argv[1]);
        LOGT("cmd_help");
        rc = 1;
        cmd_help(argc, argv);
    }

exit:
    wally_cleanup(0);
    return rc;
}

static int init(void)
{
    int rc;
    uint8_t ent[BIP39_ENTROPY_LEN_256];

    rc = wally_init(0);
    if (rc != WALLY_OK) {
        fprintf(stderr, "error: wally_init fail: %d\n", rc);
        return 1;
    }

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

static int cmd_help(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    printf("Usage: %s [options]\n", argv[0]);
    printf("\nOptions:\n");
    printf("  addr              Get addresses.\n");
    printf("  newaddr           Get new address.\n");
    printf("  tx <hex_string>   Decode transaction hex string.\n");
    printf("\n");
    printf("  spend <input_hex> <out_index> <output_address> <amount_sats> <feerate>   Decode transaction hex string.\n");
    printf("\n");
    printf("  help              Show this help message and exit.\n");

    return 0;
}

static int cmd_addresses(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    int rc = 0;
    struct wallet_address wa = WALLET_GET_ADDR_INIT;

    LOGT("get addresses");

    while (rc == 0) {
        int done = 0;
        rc = wallet_get_address(&wa, &done);
        if (rc != 0) {
            fprintf(stderr, "error: wallet_get_address fail: %d\n", rc);
            return 1;
        }
        if (done) {
            break;
        }
        printf("%s\n", wa.address);
    }

    return 0;
}

static int cmd_newaddress(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    int rc;
    char addr[ADDRESS_STR_MAX];

    LOGT("new address");
    rc = wallet_new_extr_address(addr);
    if (rc != 0) {
        fprintf(stderr, "error: wallet_new_extr_address fail: %d\n", rc);
        return 1;
    }
    printf("address: %s\n", addr);

    return 0;
}

static int cmd_tx(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Error: not enough arguments\n");
        return 1;
    }

    const char *hex_string = argv[2];

    int rc;
    struct wally_tx *tx = NULL;
    size_t len = strlen(hex_string) / 2;
    uint8_t *hex = (uint8_t *)malloc(len);
    size_t written;

    rc = wally_hex_to_bytes(hex_string, hex, len, &written);
    if (rc != WALLY_OK || written != len) {
        fprintf(stderr, "error: wally_hex_to_bytes fail: %d\n", rc);
        goto exit;
    }
    rc = tx_decode(&tx, hex, len);
    printf("valid transaction data: %s\n", rc == 0 ? "true" : "false");
    if (rc != 0) {
        fprintf(stderr, "error: tx_decode fail: %d\n", rc);
        goto exit;
    }

    printf("version: %d\n", tx->version);
    printf("locktime: %d\n", tx->locktime);
    printf("inputs: %ld\n", tx->num_inputs);
    printf("outputs: %ld\n\n", tx->num_outputs);
    for (size_t i = 0; i < tx->num_inputs; i++) {
        printf("---vin[%ld]---\n", i);
        printf("txid: ");
        dump_rev(tx->inputs[i].txhash, sizeof(tx->inputs[i].txhash));
        printf("index: %d\n", tx->inputs[i].index);
        if (tx->inputs[i].script) {
            printf("scriptSig: ");
            dump(tx->inputs[i].script, tx->inputs[i].script_len);
        }
        printf("sequence: 0x%08x\n", tx->inputs[i].sequence);
        if (tx->inputs[i].witness) {
            for (size_t j = 0; j < tx->inputs[i].witness->num_items; j++) {
                printf("witness[%ld]: ", j);
                dump(tx->inputs[i].witness->items[j].witness, tx->inputs[i].witness->items[j].witness_len);
            }
        }
    }
    printf("\n");
    char addr[ADDRESS_STR_MAX];
    for (size_t i = 0; i < tx->num_outputs; i++) {
        printf("---vout[%ld]---\n", i);
        printf("value: %ld sats\n", tx->outputs[i].satoshi);
        printf("scriptPubKey: ");
        dump(tx->outputs[i].script, tx->outputs[i].script_len);
        rc = address_from_scriptpubkey(addr, tx->outputs[i].script, tx->outputs[i].script_len);
        if (rc == 0) {
            printf("address: %s\n", addr);
        }
        int detect = 0;
        rc = wallet_search_scriptpubkey(&detect, NULL, tx->outputs[i].script, tx->outputs[i].script_len);
        if (rc == 0) {
            printf("owner: %s\n", detect ? "yes" : "no");
        }
    }

exit:
    if (tx) {
        wally_tx_free(tx);
    }
    free(hex);
    return rc;
}


static int tweak_keypair(
    uint8_t tweak_privkey[EC_PRIVATE_KEY_LEN],
    uint8_t tweak_xpubkey[EC_XONLY_PUBLIC_KEY_LEN],
    const uint8_t privkey[EC_PRIVATE_KEY_LEN])
{
    int rc;

    uint8_t pubkey[EC_PUBLIC_KEY_LEN];
    rc = wally_ec_public_key_from_private_key(
        privkey, EC_PRIVATE_KEY_LEN,
        pubkey, sizeof(pubkey));
    if (rc != WALLY_OK) {
        LOGE("error: wally_ec_public_key_from_private_key fail: %d", rc);
        return 1;
    }

    uint8_t tweak_pubkey[EC_PUBLIC_KEY_LEN];
    rc = wally_ec_public_key_bip341_tweak(
        pubkey, sizeof(pubkey),
        NULL, 0,
        0,
        tweak_pubkey, sizeof(tweak_pubkey));
    if (rc != WALLY_OK) {
        LOGE("error: wally_ec_public_key_bip341_tweak fail: %d", rc);
        return 1;
    }
    memcpy(tweak_xpubkey, tweak_pubkey + 1, EC_XONLY_PUBLIC_KEY_LEN);

    rc = wally_ec_private_key_bip341_tweak(
        privkey, EC_PRIVATE_KEY_LEN,
        NULL, 0,
        0,
        tweak_privkey, EC_PRIVATE_KEY_LEN);
    if (rc != WALLY_OK) {
        LOGE("error: wally_ec_private_key_bip341_tweak fail: %d", rc);
        return 1;
    }

    return 0;
}


static int cmd_spend(int argc, char *argv[])
{
    if (argc != 7) {
        fprintf(stderr, "Error: not enough arguments\n");
        return 1;
    }

    const char *hex_string = argv[2];
    const char *out_index_str = argv[3];
    const char *out_addr = argv[4];
    const char *amount_str = argv[5];
    const char *feerate_str = argv[6];


    int rc;
    struct wally_tx *tx = NULL;

    // check input

    struct wally_tx *input_tx = NULL;
    size_t len = strlen(hex_string) / 2;
    uint8_t *hex = wally_malloc(len);
    size_t written;
    const struct conf *conf = conf_get();

    rc = wally_hex_to_bytes(hex_string, hex, len, &written);
    if (rc != WALLY_OK || written != len) {
        fprintf(stderr, "error: wally_hex_to_bytes fail: %d\n", rc);
        goto exit;
    }

    char *endptr;
    errno = 0;

    uint32_t out_index = strtoul(out_index_str, &endptr, 10);
    if (errno != 0 || *endptr != '\0') {
        fprintf(stderr, "error: strtoul(out_index_str) fail: %s\n", out_index_str);
        goto exit;
    }
    LOGT("out_index: %d", out_index);

    // out_addr to script pubkey
    size_t out_scriptpubkey_len = 0;
    uint8_t out_scriptpubkey[WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN];
    rc = wally_addr_segwit_to_bytes(out_addr, conf->addr_family, 0, out_scriptpubkey, sizeof(out_scriptpubkey), &out_scriptpubkey_len);
    if (rc != WALLY_OK) {
        LOGE("error: wally_address_to_scriptpubkey fail: %d", rc);
        rc = wally_address_to_scriptpubkey(out_addr, conf->wally_network, out_scriptpubkey, sizeof(out_scriptpubkey), &out_scriptpubkey_len);
    }
    if (rc != WALLY_OK) {
        fprintf(stderr, "error: cannot convert address to scriptpubkey\n");
        goto exit;
    }
    LOGT("pay scriptpubkey");
    DUMPT(out_scriptpubkey, out_scriptpubkey_len);

    uint64_t amount = strtoull(amount_str, &endptr, 10);
    if (errno != 0 || *endptr != '\0') {
        fprintf(stderr, "error: strtoull(amount_str) fail: %s\n", amount_str);
        goto exit;
    }
    LOGT("amount: %ld", amount);

    double feerate = strtod(feerate_str, &endptr);
    if (errno != 0 || *endptr != '\0') {
        fprintf(stderr, "error: strtod(feerate_str) fail: %s\n", feerate_str);
        goto exit;
    }
    LOGT("feerate: %lf", feerate);

    rc = tx_decode(&input_tx, hex, len);
    if (rc != 0) {
        fprintf(stderr, "error: tx_decode fail: %d\n", rc);
        goto exit;
    }
    if (out_index >= input_tx->num_outputs) {
        fprintf(stderr, "error: out_index(%d) >= input_tx->num_outputs(%zu)\n", out_index, input_tx->num_outputs);
        goto exit;
    }
    uint8_t txhash[WALLY_TXHASH_LEN];
    char txid[TX_TXID_STR_MAX];
    rc = wally_tx_get_txid(input_tx, txhash, sizeof(txhash));
    if (rc != WALLY_OK) {
        fprintf(stderr, "error: wally_tx_get_txid fail: %d\n", rc);
        goto exit;
    }
    txhash_to_txid_string(txid, txhash);
    LOGT("txid: %s", txid);

    const struct wally_tx_output *out = &input_tx->outputs[out_index];
    int detect = 0;
    struct ext_key hdkey;
    rc = wallet_search_scriptpubkey(&detect, &hdkey, out->script, out->script_len);
    if (rc != 0) {
        fprintf(stderr, "error: wallet_search_scriptpubkey fail: %d\n", rc);
        goto exit;
    }
    if (detect == 0) {
        fprintf(stderr, "error: the outpoint(%s:%d) is not mine\n", txid, out_index);
        goto exit;
    }
    LOGT("spendable amount(including fee): %ld", out->satoshi);
    if (amount > out->satoshi) {
        fprintf(stderr, "error: amount is too large to spend\n");
        goto exit;
    }

    // お釣りが必要かどうか
    //  out->satoshi - amount - fee > dust_limit
    //  お釣りoutputが追加されると +43 vbyte
    //
    // estimate tx size
    // == weight: x4 ==
    //  * version(4)
    //  * input_num(1)
    //      * txid(32), index(4)
    //      * scriptSig(1)
    //      * sequence(4)
    //  * output_num(1)
    //      * spend:
    //          * value(8)
    //          * scriptpubkey(1+X)
    //              * X=P2PKH(25), P2SH(23), P2WPKH(22), P2WSH(34), P2TR(34)
    //      * change: P2TR
    //          * value(8)
    //          * scriptpubkey(1+34)
    //  * locktime(4)
    //
    // == weight: x1 ==
    //  * maker(1), marks(1)
    //  * witness_num(1)
    //      * witness: P2TR key path(1+64)
    uint64_t change_amount = 0;
    uint64_t dust_limit;
    rc = tx_get_dustlimit(&dust_limit, out->script, out->script_len);
    if (rc != 0) {
        fprintf(stderr, "error: tx_get_dustlimit fail: %d\n", rc);
        goto exit;
    }
    // fee with change output
    size_t weight = 4 * (4 + 1 + 36 + 1 + 4 + 1 + 8 + 1 + out_scriptpubkey_len + 8 + 1 + 34 + 4) + (2 + 1 + 1 + 64);
    uint16_t vbyte = (uint16_t)ceil(weight / 4.0);
    uint64_t fee = (uint64_t)ceil(vbyte * feerate);
    LOGT("with change output");
    LOGT("vbyte: %d", vbyte);
    LOGT("fee: %ld", fee);
    if (out->satoshi > amount + fee) {
        if (out->satoshi - (amount + fee) >= dust_limit) {
            LOGT("has_change");
            change_amount = out->satoshi - amount - fee;
        } else {
            LOGT("no_change");
        }
    } else {
        // remove change output
        vbyte -= (8 + 1 + 34);
        fee = (uint64_t)ceil(vbyte * feerate);
        LOGT("remove change output");
        LOGT("vbyte: %d", vbyte);
        LOGT("fee: %ld", fee);
        if (out->satoshi < amount + fee) {
            fprintf(stderr, "amount is too large\n");
            return 1;
        } else {
            LOGT("no_change");
        }
    }

    // create tx

    rc = wally_tx_init_alloc(
        1, // version
        0, // locktime
        1, // vin_cnt
        1, // vout_cnt
        &tx);
    if (rc != WALLY_OK) {
        fprintf(stderr, "error: wally_tx_init_alloc fail: %d", rc);
        goto exit;
    }

    struct wally_tx_input tx_input = {
        .index = out_index,
        .sequence = 0xffffffff,
        .script = NULL,
        .script_len = 0,
        .witness = NULL,
        .features = 0,
    };
    memcpy(tx_input.txhash, txhash, sizeof(txhash));
    rc = wally_tx_add_input(tx, &tx_input);
    if (rc != WALLY_OK) {
        fprintf(stderr, "error: wally_tx_add_input fail: %d", rc);
        goto exit;
    }

    char chg_addr[ADDRESS_STR_MAX];
    uint8_t chg_scriptpubkey[WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN];
    size_t chg_scriptpubkey_len = sizeof(chg_scriptpubkey);
    if (change_amount) {
        rc = wallet_new_intr_address(chg_addr, chg_scriptpubkey, &chg_scriptpubkey_len);
        if (rc != 0) {
            fprintf(stderr, "error: wallet_new_intr_address fail: %d", rc);
            goto exit;
        }
        LOGT("change address: %s", chg_addr);
        LOGT("change scriptpubkey");
        DUMPT(chg_scriptpubkey, chg_scriptpubkey_len);
    } else {
        LOGT("no change output");
    }

    const struct wally_tx_output change = {
        .satoshi = change_amount,
        .script = chg_scriptpubkey,
        .script_len = chg_scriptpubkey_len,
        .features = 0,
    };
    LOGD("amount: %ld", amount);
    const struct wally_tx_output TX_OUTPUT = {
        .satoshi = amount,
        .script = out_scriptpubkey,
        .script_len = out_scriptpubkey_len,
        .features = 0,
    };
    const struct wally_tx_output *outputs[2];
    size_t tx_output_num;
    if (change_amount) {
        tx_output_num = 2;
        if (rand() % 2 == 0) {
            outputs[0] = &TX_OUTPUT;
            outputs[1] = &change;
        } else {
            outputs[0] = &change;
            outputs[1] = &TX_OUTPUT;
        }
    } else {
        tx_output_num = 1;
        outputs[0] = &TX_OUTPUT;
    }
    for (size_t i = 0; i < tx_output_num; i++) {
        rc = wally_tx_add_output(tx, outputs[i]);
        if (rc != WALLY_OK) {
            LOGD("TX_OUTPUT[%ld].amount = %lu", i, outputs[i]->satoshi);
            LOGD("TX_OUTPUT[%ld].script:", i);
            DUMPD(outputs[i]->script, outputs[i]->script_len);
            fprintf(stderr, "error: wally_tx_add_output(%ld) fail: %d\n", i, rc);
            goto exit;
        }
    }

    struct wally_map *script_map;
    rc = wally_map_init_alloc(1, NULL, &script_map);
    if (rc != WALLY_OK) {
        fprintf(stderr, "error: wally_map_init_alloc fail: %d", rc);
        goto exit;
    }
    rc = wally_map_add_integer(
        script_map,
        0, // key
        out->script, out->script_len);
    if (rc != WALLY_OK) {
        wally_map_free(script_map);
        fprintf(stderr, "error: wally_map_add_integer fail: %d", rc);
        goto exit;
    }

    uint8_t sigHash[EC_MESSAGE_HASH_LEN];
    const uint64_t VALUES[] = { out->satoshi };
    rc = wally_tx_get_btc_taproot_signature_hash(
        tx,
        0,
        script_map, // scripts
        VALUES, ARRAY_SIZE(VALUES),
        NULL,  0, // tapleaf
        0x00, // key version
        WALLY_NO_CODESEPARATOR, // codesep position
        NULL, 0, // annex
        WALLY_SIGHASH_DEFAULT,
        0,
        sigHash, sizeof(sigHash)
    );
    wally_map_free(script_map);
    if (rc != WALLY_OK) {
        fprintf(stderr, "error: wally_tx_get_btc_taproot_signature_hash fail: %d", rc);
        goto exit;
    }

    uint8_t tweak_privkey[EC_PRIVATE_KEY_LEN];
    uint8_t tweak_xpubkey[EC_XONLY_PUBLIC_KEY_LEN];
    rc = tweak_keypair(tweak_privkey, tweak_xpubkey, &hdkey.priv_key[1]);
    if (rc != 0) {
        fprintf(stderr, "error: tweak_keypair fail: %d", rc);
        goto exit;
    }

    uint8_t sig[EC_SIGNATURE_LEN];
    rc = wally_ec_sig_from_bytes(
        tweak_privkey, sizeof(tweak_privkey),
        sigHash, sizeof(sigHash),
        EC_FLAG_SCHNORR,
        sig, EC_SIGNATURE_LEN
    );
    if (rc != WALLY_OK) {
        fprintf(stderr, "error: wally_ec_sig_from_bytes fail: %d", rc);
        goto exit;
    }

    struct wally_tx_witness_stack *witness;
    rc = wally_witness_p2tr_from_sig(sig, sizeof(sig), &witness);
    if (rc != WALLY_OK) {
        fprintf(stderr, "error: wally_witness_p2tr_from_sig fail: %d", rc);
        goto exit;
    }
    rc = wally_tx_set_input_witness(tx, 0, witness);
    if (rc != WALLY_OK) {
        fprintf(stderr, "error: wally_tx_set_input_witness fail: %d", rc);
        goto exit;
    }
    wally_tx_witness_stack_free(witness);

    uint8_t tx_data[1024];
    size_t tx_data_len = 0;
    rc = wally_tx_to_bytes(
        tx,
        WALLY_TX_FLAG_USE_WITNESS,
        tx_data, sizeof(tx_data), &tx_data_len);
    if (rc != WALLY_OK) {
        fprintf(stderr, "error: wally_tx_to_bytes fail: %d", rc);
        goto exit;
    }
    printf("raw: ");
    dump(tx_data, tx_data_len);

exit:
    if (input_tx) {
        wally_tx_free(input_tx);
    }
    if (tx) {
        wally_tx_free(tx);
    }
    wally_free(hex);
    return rc;
}
