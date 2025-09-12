#include <stddef.h>

#include "gtest/gtest.h"
#include "fff/fff.h"
#include "fakes.h"

extern "C" {
#include "../src/wallet.c"
}


namespace {
// address.c
FAKE_VALUE_FUNC(int, address_from_scriptpubkey, char *, const uint8_t *, size_t);
}

class TestWallet: public testing::Test {
    void SetUp() {
        RESET_FAKE(bip32_key_from_parent_path_str)
        RESET_FAKE(bip32_key_from_parent)
        RESET_FAKE(bip32_key_from_seed)
        RESET_FAKE(bip39_mnemonic_from_bytes)
        RESET_FAKE(bip39_mnemonic_to_seed)
        RESET_FAKE(bip39_mnemonic_validate)
        RESET_FAKE(wally_addr_segwit_from_bytes)
        RESET_FAKE(wally_free_string)
        RESET_FAKE(wally_malloc)
        RESET_FAKE(wally_scriptpubkey_p2tr_from_bytes)
        RESET_FAKE(address_from_scriptpubkey)
        FFF_RESET_HISTORY();
    }
    void TearDown() {
    }
};

////////////////////////////////////////////

TEST_F(TestWallet, create_masterkey)
{
    int rc;
    struct ext_key hdkey;
    const char MNEMONIC[] = "";

    bip39_mnemonic_to_seed_fake.return_val = WALLY_ERROR;

    rc = create_masterkey(&hdkey, MNEMONIC);
    ASSERT_EQ(bip39_mnemonic_to_seed_fake.call_count, 1U);
    ASSERT_EQ(rc, 1);
}

TEST_F(TestWallet, get_address)
{
    int rc;
    struct ext_key hdkey = {0};
    char address[ADDRESS_STR_MAX];

    rc = get_address(address, &hdkey, NULL, NULL);
    ASSERT_EQ(rc, 1);
}
