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
    printf("  spend <input_hex> <out_index> <output_address> <amount_sats> <feerate>   Create a spendable transaction.\n");
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
    size_t hex_len = strlen(hex_string) / 2;
    uint8_t *hex = (uint8_t *)wally_malloc(hex_len);
    size_t written;

    rc = wally_hex_to_bytes(hex_string, hex, hex_len, &written);
    if (rc != WALLY_OK || written != hex_len) {
        fprintf(stderr, "error: wally_hex_to_bytes fail: %d\n", rc);
        rc = 1;
        goto exit;
    }
    rc = tx_decode(&tx, hex, hex_len);
    if (rc != 0) {
        fprintf(stderr, "error: tx_decode fail: %d\n", rc);
        goto exit;
    }

    rc = tx_show_detail(tx);
    if (rc != 0) {
        fprintf(stderr, "error: tx_show_detail fail: %d\n", rc);
        goto exit;
    }

exit:
    if (tx) {
        wally_tx_free(tx);
    }
    wally_free(hex);
    return rc;
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
    struct tx_spend_1in_1out param;
    size_t written;
    char *endptr;
    const struct conf *conf = conf_get();

    size_t hex_len = strlen(hex_string) / 2;
    uint8_t *hex = wally_malloc(hex_len);
    rc = wally_hex_to_bytes(hex_string, hex, hex_len, &written);
    if (rc != WALLY_OK || written != hex_len) {
        fprintf(stderr, "error: wally_hex_to_bytes fail: %d\n", rc);
        goto exit;
    }

    param.input_tx = NULL;
    rc = tx_decode(&param.input_tx, hex, hex_len);
    if (rc != 0) {
        fprintf(stderr, "error: tx_decode fail: %d\n", rc);
        goto exit;
    }

    errno = 0;
    param.out_index = strtoul(out_index_str, &endptr, 10);
    if (errno != 0 || *endptr != '\0') {
        fprintf(stderr, "error: strtoul(out_index_str) fail: %s\n", out_index_str);
        rc = 1;
        goto exit;
    }
    LOGT("out_index: %d", param.out_index);

    // out_addr to script pubkey
    param.out_scriptpubkey_len = 0;
    uint8_t out_scriptpubkey[WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN];
    param.out_scriptpubkey = out_scriptpubkey;
    rc = wally_addr_segwit_to_bytes(out_addr, conf->addr_family, 0, out_scriptpubkey, sizeof(out_scriptpubkey), &param.out_scriptpubkey_len);
    if (rc != WALLY_OK) {
        fprintf(stderr, "error: wally_address_to_scriptpubkey fail: %d\n", rc);
        rc = wally_address_to_scriptpubkey(out_addr, conf->wally_network, out_scriptpubkey, sizeof(out_scriptpubkey), &param.out_scriptpubkey_len);
    }
    if (rc != WALLY_OK) {
        fprintf(stderr, "error: cannot convert address to scriptpubkey\n");
        goto exit;
    }

    param.amount = strtoull(amount_str, &endptr, 10);
    if (errno != 0 || *endptr != '\0') {
        fprintf(stderr, "error: strtoull(amount_str) fail: %s\n", amount_str);
        rc = 1;
        goto exit;
    }
    LOGT("amount: %ld", param.amount);

    param.feerate = strtod(feerate_str, &endptr);
    if (errno != 0 || *endptr != '\0') {
        fprintf(stderr, "error: strtod(feerate_str) fail: %s\n", feerate_str);
        rc = 1;
        goto exit;
    }
    LOGT("feerate: %lf", param.feerate);

    rc = tx_create_spend_1in_1out(&tx, &param);
    if (rc != 0) {
        fprintf(stderr, "error: tx_create_spend_1in_1out fail: %d\n", rc);
        goto exit;
    }

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
    uint8_t txhash[WALLY_TXHASH_LEN];
    char txid[TX_TXID_STR_MAX];
    rc = wally_tx_get_txid(tx, txhash, sizeof(txhash));
    if (rc != WALLY_OK) {
        fprintf(stderr, "error: wally_tx_get_txid fail: %d\n", rc);
        goto exit;
    }
    txhash_to_txid_string(txid, txhash);
    printf("txid: %s\n", txid);
    printf("hex: ");
    dump(tx_data, tx_data_len);

exit:
    if (tx) {
        wally_tx_free(tx);
    }
    wally_tx_free(param.input_tx);
    wally_free(hex);
    return rc;
}
