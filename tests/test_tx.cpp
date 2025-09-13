#include <stddef.h>
#include <stdint.h>

#include "gtest/gtest.h"
#include "fff/fff.h"
#include "fakes.h"

extern "C" {
#include "../src/tx.c"
}

class TestAddress: public testing::Test {
    void SetUp() {
        RESET_FAKE(wally_scriptpubkey_get_type)
        // RESET_FAKE(wally_scriptpubkey_to_address)
        // RESET_FAKE(wally_addr_segwit_to_bytes)
        // RESET_FAKE(wally_address_to_scriptpubkey)
        // RESET_FAKE(wally_addr_segwit_from_bytes)
        FFF_RESET_HISTORY();
    }
    void TearDown() {
    }
};

////////////////////////////////////////////

TEST_F(TestAddress, tx_get_dustlimit)
{
    int rc;

    wally_scriptpubkey_get_type_fake.custom_fake = [](
        const unsigned char *a, size_t b, size_t *c)
    -> int {
        *c = WALLY_SCRIPT_TYPE_P2PKH;
        return 0;
    };

    uint64_t dustlimit;
    rc = tx_get_dustlimit(&dustlimit, NULL, 0);
    ASSERT_EQ(wally_scriptpubkey_get_type_fake.call_count, 1U);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(dustlimit, 546UL);
}
