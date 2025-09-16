#include <stddef.h>
#include <stdint.h>

#include "gtest/gtest.h"
#include "fff.h"
#include "fakes.h"

extern "C" {
#include "../src/address.c"
}

class TestAddress: public testing::Test {
    void SetUp() {
        fakes_init();
    }
    void TearDown() {
    }
};

////////////////////////////////////////////

TEST_F(TestAddress, address_from_scriptpubkey_witness)
{
    int rc;
    static char OUTPUT[] = "TEST";

    const size_t TYPES[] = {
        WALLY_SCRIPT_TYPE_P2WPKH,
        WALLY_SCRIPT_TYPE_P2WSH,
        WALLY_SCRIPT_TYPE_P2TR,
    };
    static size_t type;
    for (size_t i = 0; i < ARRAY_SIZE(TYPES); i++) {
        type = TYPES[i];
        wally_scriptpubkey_get_type_fake.custom_fake = [](
            const unsigned char *a, size_t b, size_t *c)
        -> int {
            *c = type;
            return 0;
        };
        wally_addr_segwit_from_bytes_fake.custom_fake = [](
            const unsigned char *bytes,
            size_t bytes_len,
            const char *addr_family,
            uint32_t flags,
            char **output)
        -> int {
            *output = OUTPUT;
            return 0;
        };

        char address[ADDRESS_STR_MAX];
        rc = address_from_scriptpubkey(address, NULL, 0);
        ASSERT_EQ(rc, 0);
        ASSERT_EQ(strcmp(address, OUTPUT), 0);
    }
}

TEST_F(TestAddress, address_from_scriptpubkey_p2pkh)
{
    int rc;
    static char OUTPUT[] = "TEST";

    wally_scriptpubkey_get_type_fake.custom_fake = [](
        const unsigned char *a, size_t b, size_t *c)
    -> int {
        *c = WALLY_SCRIPT_TYPE_P2PKH;
        return 0;
    };
    wally_scriptpubkey_to_address_fake.custom_fake = [](
        const unsigned char *scriptpubkey,
        size_t scriptpubkey_len,
        uint32_t network,
        char **output)
    -> int {
        *output = OUTPUT;
        return 0;
    };

    char address[ADDRESS_STR_MAX];
    rc = address_from_scriptpubkey(address, NULL, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(strcmp(address, OUTPUT), 0);
}

TEST_F(TestAddress, address_from_scriptpubkey_get_type_error)
{
    int rc;

    wally_scriptpubkey_get_type_fake.custom_fake = [](
        const unsigned char *a, size_t b, size_t *c)
    -> int {
        return WALLY_ERROR;
    };

    char address[ADDRESS_STR_MAX];
    rc = address_from_scriptpubkey(address, NULL, 0);
    ASSERT_EQ(rc, 1);
}

TEST_F(TestAddress, address_from_scriptpubkey_segwit_from_bytes_error)
{
    int rc;

    wally_scriptpubkey_get_type_fake.custom_fake = [](
        const unsigned char *a, size_t b, size_t *c)
    -> int {
        *c = WALLY_SCRIPT_TYPE_P2TR;
        return 0;
    };
    wally_addr_segwit_from_bytes_fake.custom_fake = [](
        const unsigned char *bytes,
        size_t bytes_len,
        const char *addr_family,
        uint32_t flags,
        char **output)
    -> int {
        return 1;
    };

    char address[ADDRESS_STR_MAX];
    rc = address_from_scriptpubkey(address, NULL, 0);
    ASSERT_EQ(rc, 1);
}

TEST_F(TestAddress, address_from_scriptpubkey_p2pkh_error)
{
    int rc;

    wally_scriptpubkey_get_type_fake.custom_fake = [](
        const unsigned char *a, size_t b, size_t *c)
    -> int {
        *c = WALLY_SCRIPT_TYPE_P2PKH;
        return 0;
    };
    wally_scriptpubkey_to_address_fake.custom_fake = [](
        const unsigned char *scriptpubkey,
        size_t scriptpubkey_len,
        uint32_t network,
        char **output)
    -> int {
        return 1;
    };

    char address[ADDRESS_STR_MAX];
    rc = address_from_scriptpubkey(address, NULL, 0);
    ASSERT_EQ(rc, 1);
}

TEST_F(TestAddress, address_to_scriptpubkey_segwit)
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
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(len, (size_t)3);
    ASSERT_EQ(scriptpubkey[0], 1);
    ASSERT_EQ(scriptpubkey[1], 2);
    ASSERT_EQ(scriptpubkey[2], 3);
}

TEST_F(TestAddress, address_to_scriptpubkey_nonsegwit)
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
        return WALLY_EINVAL;
    };
    wally_address_to_scriptpubkey_fake.custom_fake = [](
        const char *addr,
        uint32_t network,
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
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(len, (size_t)3);
    ASSERT_EQ(scriptpubkey[0], 1);
    ASSERT_EQ(scriptpubkey[1], 2);
    ASSERT_EQ(scriptpubkey[2], 3);
}


TEST_F(TestAddress, address_to_scriptpubkey_nonsegwit_error)
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
        return WALLY_EINVAL;
    };
    wally_address_to_scriptpubkey_fake.custom_fake = [](
        const char *addr,
        uint32_t network,
        unsigned char *bytes_out,
        size_t len,
        size_t *written)
    -> int {
        return 1;
    };

    uint8_t scriptpubkey[WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN];
    size_t len;
    rc = address_to_scriptpubkey(scriptpubkey, &len, "");
    ASSERT_EQ(rc, 1);
}
