#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_address.h>
#include <wally_map.h>
#include <wally_script.h>

#include "address.h"
#include "conf.h"
#include "log.h"
#include "misc.h"
#include "tx.h"
#include "wallet.h"

/////////////////////////////////////////////////
// Prototype definitions
/////////////////////////////////////////////////

static int decode_raw(struct wally_tx **tx, const uint8_t *data, size_t len);
static int tweak_keypair(
    uint8_t tweak_privkey[EC_PRIVATE_KEY_LEN],
    uint8_t tweak_xpubkey[EC_XONLY_PUBLIC_KEY_LEN],
    const uint8_t privkey[EC_PRIVATE_KEY_LEN]);
static int calc_change_amount(
    uint64_t *change_amount,
    const struct tx_spend_1in_1out *param,
    const struct wally_tx_output *out);
static int tx_spned_1in_1out(
    struct wally_tx **tx,
    const struct tx_spend_1in_1out *param,
    const struct wally_tx_output *prevout,
    const struct ext_key *hdkey,
    const uint8_t txhash[WALLY_TXHASH_LEN],
    uint64_t change_amount);
static int tx_1_input(
    struct wally_tx *tx,
    struct wally_tx_input *tx_input,
    const struct tx_spend_1in_1out *param,
    const uint8_t txhash[WALLY_TXHASH_LEN]);
static int tx_1_output(
    struct wally_tx *tx,
    struct wally_tx_output *tx_output,
    struct wally_tx_output *tx_change,
    const struct tx_spend_1in_1out *param,
    uint64_t change_amount);
static int tx_1_witness(
    struct wally_tx *tx,
    const struct ext_key *hdkey,
    const struct wally_tx_output *prevout);

/////////////////////////////////////////////////
// Public functions
/////////////////////////////////////////////////

int tx_get_dustlimit(uint64_t *dustlimit, const uint8_t *scriptpubkey, size_t len)
{
    int rc;

    size_t type;
    rc = wally_scriptpubkey_get_type(scriptpubkey, len, &type);
    if (rc != WALLY_OK) {
        LOGE("error: wally_scriptpubkey_get_type fail: %d", rc);
        return 1;
    }
    // https://github.com/lightning/bolts/issues/905
    // https://chatgpt.com/share/68bb6fd5-afac-8001-aa9e-aca051311b8e
    switch (type) {
        case WALLY_SCRIPT_TYPE_P2PKH:
            *dustlimit = 546;
            break;
        case WALLY_SCRIPT_TYPE_P2SH:
            *dustlimit = 540;
            break;
        case WALLY_SCRIPT_TYPE_P2WPKH:
            *dustlimit = 294;
            break;
        case WALLY_SCRIPT_TYPE_P2WSH:
        case WALLY_SCRIPT_TYPE_P2TR:
            *dustlimit = 330;
            break;
        default:
            LOGE("error: unknown script type: %d", (int)type);
            return 1;
    }
    return 0;
}

int tx_get_scriptpubkey_len(size_t *len, size_t type)
{
    switch (type) {
        case WALLY_SCRIPT_TYPE_P2PKH:
            *len = 25;
            break;
        case WALLY_SCRIPT_TYPE_P2SH:
            *len = 23;
            break;
        case WALLY_SCRIPT_TYPE_P2WPKH:
            *len = 22;
            break;
        case WALLY_SCRIPT_TYPE_P2WSH:
        case WALLY_SCRIPT_TYPE_P2TR:
            *len = 34;
            break;
        default:
            LOGE("error: unknown script type: %d", (int)type);
            return 1;
    }
    return 0;
}

int tx_decode(struct wally_tx **tx, const uint8_t *data, size_t len)
{
    int rc;

    rc = decode_raw(tx, data, len);
    if (rc != 0) {
        LOGE("error: decode_raw fail: %d", rc);
        return 1;
    }
    return 0;
}

int tx_show_detail(const struct wally_tx *tx)
{
    int rc;

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

    return 0;
}

int tx_create_spend_1in_1out(struct wally_tx **tx, const struct tx_spend_1in_1out *param)
{
    int rc;
    const struct wally_tx *input_tx = param->input_tx;

    if (param->out_index >= input_tx->num_outputs) {
        LOGE("error: out_index(%d) >= input_tx->num_outputs(%zu)", param->out_index, input_tx->num_outputs);
        return 1;
    }

    uint8_t txhash[WALLY_TXHASH_LEN];
    rc = wally_tx_get_txid(input_tx, txhash, sizeof(txhash));
    if (rc != WALLY_OK) {
        LOGE("error: wally_tx_get_txid fail: %d", rc);
        return 1;
    }

    const struct wally_tx_output *prevout = &input_tx->outputs[param->out_index];
    int detect = 0;
    struct ext_key hdkey;
    rc = wallet_search_scriptpubkey(&detect, &hdkey, prevout->script, prevout->script_len);
    if (rc != 0) {
        LOGE("error: wallet_search_scriptpubkey fail: %d", rc);
        return 1;
    }
    if (detect == 0) {
        LOGE("error: the out_index(%d) is not mine", param->out_index);
        return 1;
    }

    LOGT("spendable amount(including fee): %ld", prevout->satoshi);
    if (param->amount > prevout->satoshi) {
        LOGE("error: amount is too large to spend");
        return 1;
    }

    uint64_t change_amount = 0;
    rc = calc_change_amount(&change_amount, param, prevout);
    if (rc != 0) {
        LOGE("error: calc_change_amount fail: %d", rc);
        return 1;
    }

    // create tx
    rc = tx_spned_1in_1out(tx, param, prevout, &hdkey, txhash, change_amount);
    if (rc != 0) {
        LOGE("error: tx_spned_1in_1out fail: %d", rc);
        return 1;
    }

    return 0;
}

/////////////////////////////////////////////////
// Private functions
/////////////////////////////////////////////////

static int decode_raw(struct wally_tx **tx, const uint8_t *data, size_t len)
{
    int rc;
    const uint32_t flags[] = { WALLY_TX_FLAG_USE_WITNESS, 0 };

    for (size_t i = 0; i < ARRAY_SIZE(flags); i++) {
        rc = wally_tx_from_bytes(data, len, flags[i], tx);
        if (rc == WALLY_OK) {
            return 0;
        }
    }
    return 1;
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

// need change output?
//  out->satoshi - amount - fee > dust_limit
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
static int calc_change_amount(
    uint64_t *change_amount,
    const struct tx_spend_1in_1out *param,
    const struct wally_tx_output *out)
{
    int rc;

    uint64_t dust_limit;
    rc = tx_get_dustlimit(&dust_limit, out->script, out->script_len);
    if (rc != 0) {
        LOGE("error: tx_get_dustlimit fail: %d", rc);
        return 1;
    }
    // fee with change output
    size_t weight = 4 * (4 + 1 + 36 + 1 + 4 + 1 + 8 + 1 + param->out_scriptpubkey_len + 8 + 1 + 34 + 4) + (2 + 1 + 1 + 64);
    uint16_t vbyte = (uint16_t)ceil(weight / 4.0);
    uint64_t fee = (uint64_t)ceil(vbyte * param->feerate);
    LOGT("with change output");
    LOGT("vbyte: %d", vbyte);
    LOGT("fee: %ld", fee);
    if (out->satoshi > param->amount + fee) {
        if (out->satoshi - (param->amount + fee) >= dust_limit) {
            LOGT("has_change");
            *change_amount = out->satoshi - param->amount - fee;
        } else {
            LOGT("no_change");
        }
    } else {
        // remove change output
        vbyte -= (8 + 1 + 34);
        fee = (uint64_t)ceil(vbyte * param->feerate);
        LOGT("remove change output");
        LOGT("vbyte: %d", vbyte);
        LOGT("fee: %ld", fee);
        if (out->satoshi < param->amount + fee) {
            LOGE("amount is too large");
            return 1;
        } else {
            LOGT("no_change");
        }
    }

    return 0;
}

static int tx_spned_1in_1out(
    struct wally_tx **tx,
    const struct tx_spend_1in_1out *param,
    const struct wally_tx_output *prevout,
    const struct ext_key *hdkey,
    const uint8_t txhash[WALLY_TXHASH_LEN],
    uint64_t change_amount)
{
    int rc;

    rc = wally_tx_init_alloc(
        1, // version
        0, // locktime
        1, // vin_cnt
        1, // vout_cnt
        tx);
    if (rc != WALLY_OK) {
        LOGE("error: wally_tx_init_alloc fail: %d", rc);
        return 1;
    }

    struct wally_tx_input tx_input;
    rc = tx_1_input(*tx, &tx_input, param, txhash);
    if (rc != 0) {
        LOGE("error: tx_1_input fail: %d", rc);
        return 1;
    }

    struct wally_tx_output tx_output;
    struct wally_tx_output tx_change;
    rc = tx_1_output(*tx, &tx_output, &tx_change, param, change_amount);
    if (rc != 0) {
        LOGE("error: tx_1_output fail: %d", rc);
        return 1;
    }

    // add witness
    rc = tx_1_witness(*tx, hdkey, prevout);
    if (rc != 0) {
        LOGE("error: tx_1_witness fail: %d", rc);
        return 1;
    }

    return 0;
}

static int tx_1_input(
    struct wally_tx *tx,
    struct wally_tx_input *tx_input,
    const struct tx_spend_1in_1out *param,
    const uint8_t txhash[WALLY_TXHASH_LEN])
{
    memcpy(tx_input->txhash, txhash, WALLY_TXHASH_LEN);
    tx_input->index = param->out_index;
    tx_input->sequence = DEFAULT_SEQUENCE;
    tx_input->script = NULL;
    tx_input->script_len = 0;
    tx_input->witness = NULL;
    tx_input->features = 0;

    int rc = wally_tx_add_input(tx, tx_input);
    if (rc != WALLY_OK) {
        LOGE("error: wally_tx_add_input fail: %d", rc);
        return 1;
    }

    return 0;
}

static int tx_1_output(
    struct wally_tx *tx,
    struct wally_tx_output *tx_output,
    struct wally_tx_output *tx_change,
    const struct tx_spend_1in_1out *param,
    uint64_t change_amount)
{
    int rc;

    tx_output->satoshi = param->amount;
    tx_output->script = param->out_scriptpubkey;
    tx_output->script_len = param->out_scriptpubkey_len;
    tx_output->features = 0;

    const struct wally_tx_output *outputs[2];
    size_t tx_output_num;
    if (change_amount) {
        char chg_addr[ADDRESS_STR_MAX];
        uint8_t chg_scriptpubkey[WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN];
        size_t chg_scriptpubkey_len = sizeof(chg_scriptpubkey);
        rc = wallet_new_intr_address(chg_addr, chg_scriptpubkey, &chg_scriptpubkey_len);
        if (rc != 0) {
            LOGE("error: wallet_new_intr_address fail: %d", rc);
            return 1;
        }
        LOGT("change address: %s", chg_addr);

        tx_change->satoshi = change_amount;
        tx_change->script = chg_scriptpubkey;
        tx_change->script_len = chg_scriptpubkey_len;
        tx_change->features = 0;

        tx_output_num = 2;
        uint8_t r;
        fill_random(&r, sizeof(r));
        if (r % 2 == 0) {
            outputs[0] = tx_output;
            outputs[1] = tx_change;
        } else {
            outputs[0] = tx_change;
            outputs[1] = tx_output;
        }
    } else {
        LOGT("no change output");
        tx_output_num = 1;
        outputs[0] = tx_output;
    }
    for (size_t i = 0; i < tx_output_num; i++) {
        rc = wally_tx_add_output(tx, outputs[i]);
        if (rc != WALLY_OK) {
            LOGE("error: wally_tx_add_output(%ld) fail: %d", i, rc);
            return 1;
        }
    }

    return 0;
}

static int tx_1_witness(
    struct wally_tx *tx,
    const struct ext_key *hdkey,
    const struct wally_tx_output *prevout)
{
    int rc;
    struct wally_map *script_map = NULL;

    rc = wally_map_init_alloc(1, NULL, &script_map);
    if (rc != WALLY_OK) {
        LOGE("error: wally_map_init_alloc fail: %d", rc);
        return 1;
    }
    rc = wally_map_add_integer(
        script_map,
        0, // vin#0
        prevout->script, prevout->script_len);
    if (rc != WALLY_OK) {
        wally_map_free(script_map);
        LOGE("error: wally_map_add_integer fail: %d", rc);
        return 1;
    }

    uint8_t sigHash[EC_MESSAGE_HASH_LEN];
    const uint64_t VALUES[] = { prevout->satoshi };
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
        LOGE("error: wally_tx_get_btc_taproot_signature_hash fail: %d", rc);
        return 1;
    }

    uint8_t tweak_privkey[EC_PRIVATE_KEY_LEN];
    uint8_t tweak_xpubkey[EC_XONLY_PUBLIC_KEY_LEN];
    rc = tweak_keypair(tweak_privkey, tweak_xpubkey, &hdkey->priv_key[1]);
    if (rc != 0) {
        LOGE("error: tweak_keypair fail: %d", rc);
        return 1;
    }

    uint8_t sig[EC_SIGNATURE_LEN];
    rc = wally_ec_sig_from_bytes(
        tweak_privkey, sizeof(tweak_privkey),
        sigHash, sizeof(sigHash),
        EC_FLAG_SCHNORR,
        sig, EC_SIGNATURE_LEN
    );
    if (rc != WALLY_OK) {
        LOGE("error: wally_ec_sig_from_bytes fail: %d", rc);
        return 1;
    }

    struct wally_tx_witness_stack *witness;
    rc = wally_witness_p2tr_from_sig(sig, sizeof(sig), &witness);
    if (rc != WALLY_OK) {
        LOGE("error: wally_witness_p2tr_from_sig fail: %d", rc);
        return 1;
    }
    rc = wally_tx_set_input_witness(tx, 0, witness);
    wally_tx_witness_stack_free(witness);
    if (rc != WALLY_OK) {
        LOGE("error: wally_tx_set_input_witness fail: %d", rc);
        return 1;
    }

    return 0;
}
