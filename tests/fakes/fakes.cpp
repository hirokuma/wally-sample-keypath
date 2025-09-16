#include "fakes.h"
#include <sys/random.h>

void fakes_init()
{
    conf_get_fake.custom_fake = []() -> const struct conf* {
        static const struct conf DEFAULT_CONF = {
            .network = NETWORK_REGTEST,
            .wally_network = WALLY_NETWORK_BITCOIN_REGTEST,
            .addr_family = "bcrt"
        };
        return &DEFAULT_CONF;
    };

    RESET_FAKE(address_from_scriptpubkey)
    RESET_FAKE(address_to_scriptpubkey)
    RESET_FAKE(dump)
    RESET_FAKE(dump_rev)
    RESET_FAKE(fill_random)
    RESET_FAKE(txhash_to_txid_string)
    RESET_FAKE(tx_create_spend_1in_1out)
    RESET_FAKE(tx_decode)
    RESET_FAKE(tx_get_dustlimit)
    RESET_FAKE(tx_get_scriptpubkey_len)
    RESET_FAKE(tx_show_detail)
    RESET_FAKE(wallet_get_address)
    RESET_FAKE(wallet_init)
    RESET_FAKE(wallet_new_extr_address)
    RESET_FAKE(wallet_new_intr_address)
    RESET_FAKE(wallet_search_scriptpubkey)

    RESET_FAKE(bip32_key_from_parent_path_str)
    RESET_FAKE(bip32_key_from_parent)
    RESET_FAKE(bip32_key_from_seed)
    RESET_FAKE(bip39_mnemonic_from_bytes)
    RESET_FAKE(bip39_mnemonic_to_seed)
    RESET_FAKE(bip39_mnemonic_validate)
    RESET_FAKE(wally_malloc)
    RESET_FAKE(wally_addr_segwit_from_bytes)
    RESET_FAKE(wally_addr_segwit_to_bytes)
    RESET_FAKE(wally_address_to_scriptpubkey)
    RESET_FAKE(wally_free_string)
    RESET_FAKE(wally_scriptpubkey_p2tr_from_bytes)
    RESET_FAKE(wally_scriptpubkey_get_type)
    RESET_FAKE(wally_scriptpubkey_to_address)
    RESET_FAKE(wally_ec_private_key_bip341_tweak)
    RESET_FAKE(wally_ec_public_key_bip341_tweak)
    RESET_FAKE(wally_ec_public_key_from_private_key)
    RESET_FAKE(wally_ec_sig_from_bytes)
    RESET_FAKE(wally_map_add_integer)
    RESET_FAKE(wally_map_free)
    RESET_FAKE(wally_map_init_alloc)
    RESET_FAKE(wally_tx_add_input)
    RESET_FAKE(wally_tx_add_output)
    RESET_FAKE(wally_tx_from_bytes)
    RESET_FAKE(wally_tx_get_btc_taproot_signature_hash)
    RESET_FAKE(wally_tx_get_txid)
    RESET_FAKE(wally_tx_init_alloc)
    RESET_FAKE(wally_tx_set_input_witness)
    RESET_FAKE(wally_tx_witness_stack_free)
    RESET_FAKE(wally_witness_p2tr_from_sig)

    RESET_FAKE(stat)
    RESET_FAKE(fopen)
    RESET_FAKE(fgets)
    RESET_FAKE(fclose)
    RESET_FAKE(fscanf)

    FFF_RESET_HISTORY();
}

void fakes_data(void *data, size_t len)
{
    getrandom(data, len, 0);
}
