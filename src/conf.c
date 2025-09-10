#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <wally_address.h>

#include "conf.h"
#include "log.h"

/////////////////////////////////////////////////
// Global variables
/////////////////////////////////////////////////

static struct conf g_conf;

/////////////////////////////////////////////////
// Prototype definitions
/////////////////////////////////////////////////

static int parse_line(const char *line);

/////////////////////////////////////////////////
// Public functions
/////////////////////////////////////////////////

int conf_load(const char *config_filename) {
    // Set default values
    g_conf.network = NETWORK_NONE;
    g_conf.addr_family = NULL;

    FILE *fp = fopen(config_filename, "r");
    if (fp == NULL) {
        LOGE("Could not open config file '%s'.", config_filename);
        return 1;
    }

    int rc;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        // Ignore comments and empty lines
        if (line[0] == '#' || line[0] == ';' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }
        rc = parse_line(line);
        if (rc != 0) {
            LOGE("Error parsing line: %s", line);
            break;
        }
    }

    fclose(fp);
    return rc;
}

const struct conf *conf_get(void) {
    return &g_conf;
}

/////////////////////////////////////////////////
// Private functions
/////////////////////////////////////////////////

static int parse_line(const char *line) {
    char key[64];
    char value[256];

    if (sscanf(line, "%63[^=]=%255[^\n]", key, value) != 2) {
        LOGE("Not a key-value pair, or format error");
        return 1;
    }

    if (strcmp(key, "network") == 0) {
        if (strcmp(value, "mainnet") == 0) {
#ifdef CONF_DISABLE_MAINNET
            LOGE("\"mainnet\" not supported");
            return 1;
#else // CONF_DISABLE_MAINNET
            LOGT("conf.network = NETWORK_MAINNET");
            g_conf.network = NETWORK_MAINNET;
            g_conf.wally_network = WALLY_NETWORK_BITCOIN_MAINNET;
            g_conf.addr_family = "bc";
#endif //
        } else if (strcmp(value, "testnet") == 0) {
            LOGE("\"testnet\" not supported(testnet3 or testnet4)");
            return 1;
        } else if (strcmp(value, "testnet3") == 0) {
            LOGT("conf.network = NETWORK_TESTNET3");
            g_conf.network = NETWORK_TESTNET3;
            g_conf.wally_network = WALLY_NETWORK_BITCOIN_TESTNET;
            g_conf.addr_family = "tb";
        } else if (strcmp(value, "testnet4") == 0) {
            LOGT("conf.network = NETWORK_TESTNET4");
            g_conf.network = NETWORK_TESTNET4;
            g_conf.wally_network = WALLY_NETWORK_BITCOIN_TESTNET;
            g_conf.addr_family = "tb";
        } else if (strcmp(value, "signet") == 0) {
            LOGT("conf.network = NETWORK_SIGNET");
            g_conf.network = NETWORK_SIGNET;
            g_conf.wally_network = WALLY_NETWORK_BITCOIN_TESTNET;
            g_conf.addr_family = "tb";
        } else if (strcmp(value, "regtest") == 0) {
            LOGT("conf.network = NETWORK_REGTEST");
            g_conf.network = NETWORK_REGTEST;
            g_conf.wally_network = WALLY_NETWORK_BITCOIN_REGTEST;
            g_conf.addr_family = "bcrt";
        } else {
            LOGE("Unknown network type: %s", value);
            return 1;
        }
    } else {
        LOGE("Unknown setting: %s=%s", key, value);
        return 1;
    }

    return 0;
}
