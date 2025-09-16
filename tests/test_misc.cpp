#include <stddef.h>

#include "gtest/gtest.h"
#include "fff.h"
#include "fakes.h"

extern "C" {
#include "../src/misc.c"
}

class TestMisc: public testing::Test {
    void SetUp() {
        fakes_init();
    }
    void TearDown() {
    }
};

////////////////////////////////////////////

TEST_F(TestMisc, dump)
{
    const uint8_t DATA[] = { 1, 2, 3 };
    dump(DATA, sizeof(DATA));
    dump(NULL, 0);
}

TEST_F(TestMisc, dump_rev)
{
    const uint8_t DATA[] = { 1, 2, 3 };
    dump_rev(DATA, sizeof(DATA));
    dump_rev(NULL, 0);
}

TEST_F(TestMisc, fill_random)
{
    const uint8_t DATA[] =  {1, 2, 3};
    uint8_t data[3];
    memcpy(data, DATA, sizeof(DATA));
    int rc = fill_random(data, sizeof(data));
    ASSERT_EQ(rc, 0);
    ASSERT_NE(memcmp(data, DATA, sizeof(DATA)), 0);
}

TEST_F(TestMisc, txhash_to_txid_string)
{
    const char TXID[] = "00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100";
    const uint8_t TXHASH[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    };

    char txid[TX_TXID_STR_MAX];
    txhash_to_txid_string(txid, TXHASH);
    ASSERT_STREQ(txid, TXID);
}
