#include <stddef.h>
#include <stdint.h>

#include "gtest/gtest.h"
#include "fff/fff.h"
#include "fakes.h"

extern "C" {
#include "../src/address.c"
}

// conf.c
FAKE_VALUE_FUNC(const struct conf *, conf_get);

class TestAddress: public testing::Test {
    void SetUp() {
        RESET_FAKE(wally_scriptpubkey_get_type)
        RESET_FAKE(wally_scriptpubkey_to_address)
        RESET_FAKE(wally_addr_segwit_to_bytes)
        RESET_FAKE(wally_address_to_scriptpubkey)
        RESET_FAKE(wally_addr_segwit_from_bytes)
        RESET_FAKE(conf_get)
        FFF_RESET_HISTORY();
    }
    void TearDown() {
    }
};

////////////////////////////////////////////

TEST_F(TestAddress, address_get_dustlimit)
{
    int rc;

    wally_scriptpubkey_get_type_fake.custom_fake = [](
        const unsigned char *a, size_t b, size_t *c)
    -> int {
        *c = WALLY_SCRIPT_TYPE_P2PKH;
        return 0;
    };

    uint64_t dustlimit;
    rc = address_get_dustlimit(&dustlimit, NULL, 0);
    ASSERT_EQ(wally_scriptpubkey_get_type_fake.call_count, 1U);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(dustlimit, 546UL);
}

// TEST_F(TestAddress, address_from_scriptpubkey)
// {
//     int rc;

//     wally_scriptpubkey_get_type_fake.custom_fake = [](
//         const unsigned char *a, size_t b, size_t *c)
//     -> int {
//         *c = WALLY_SCRIPT_TYPE_P2PKH;
//         return 0;
//     };

//     char address[ADDRESS_STR_MAX];
//     rc = address_from_scriptpubkey(address, NULL, 0);
//     ASSERT_EQ(wally_scriptpubkey_get_type_fake.call_count, 1U);
//     ASSERT_EQ(rc, 0);
// }

TEST_F(TestAddress, address_to_scriptpubkey)
{
    int rc;

    wally_addr_segwit_to_bytes_fake.custom_fake = [](
        const char *addr,
        const char *addr_family,
        uint32_t flags,
        unsigned char *bytes_out,
        size_t len,
        size_t *written)
    -> int {
        bytes_out[0] = 1;
        bytes_out[1] = 2;
        bytes_out[2] = 3;
        *written = 3;
        return 0;
    };

    uint8_t scriptpubkey[WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN];
    size_t len;
    rc = address_to_scriptpubkey(scriptpubkey, &len, "");
    ASSERT_EQ(wally_scriptpubkey_get_type_fake.call_count, 1U);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(len, (size_t)3);
    ASSERT_EQ(scriptpubkey[0], 1);
    ASSERT_EQ(scriptpubkey[1], 2);
    ASSERT_EQ(scriptpubkey[2], 3);
}
