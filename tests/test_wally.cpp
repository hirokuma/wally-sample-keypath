// libwally-coreのテストではなく、libwally-core APIの使い方が正しいかのテスト

#include <stddef.h>

#include <wally_crypto.h>
#include <wally_bip32.h>
#include <wally_bip39.h>

#include "misc.h"

#include "gtest/gtest.h"
#include "fff.h"

class TestWally: public testing::Test {
    void SetUp() {
        FFF_RESET_HISTORY();
    }
    void TearDown() {
    }
};

////////////////////////////////////////////

#include "test_wally_testvec_bip39.inc"

TEST_F(TestWally, mnemonic_to_seed_success)
{
    int rc;
    uint8_t vec_seed[BIP39_SEED_LEN_512];
    uint8_t seed[BIP39_SEED_LEN_512];
    size_t written;

    for (size_t i = 0 ; i < ARRAY_SIZE(bip39_test_vectors); i++) {
        rc = wally_hex_to_bytes(bip39_test_vectors[i].seed, vec_seed, sizeof(vec_seed), &written);
        ASSERT_EQ(rc, WALLY_OK);
        ASSERT_EQ(written, (size_t)BIP39_SEED_LEN_512);

        rc = bip39_mnemonic_to_seed(bip39_test_vectors[i].mnemonic, bip39_test_vectors_passphrase, seed, sizeof(seed), &written);
        ASSERT_EQ(rc, WALLY_OK);
        ASSERT_EQ(written, (size_t)BIP39_SEED_LEN_512);

        ASSERT_EQ(memcmp(seed, vec_seed, BIP39_SEED_LEN_512), 0);
    }
}

TEST_F(TestWally, mnemonic_to_seed_fail)
{
    int rc;
    uint8_t seed[BIP39_SEED_LEN_512];
    size_t written;

    // change bip39_test_vectors[0].mnemonic
    //                          "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    rc = bip39_mnemonic_to_seed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", bip39_test_vectors_passphrase, seed, sizeof(seed), &written);
    ASSERT_EQ(rc, WALLY_OK);
}

////////////////////////////////////////////

#include "test_wally_testvec_bip32.inc"

static void path_test_hex_to_vector(uint8_t *vec_chaincode, uint8_t *vec_priv, uint8_t *vec_pub, const struct Bip32TestVector* vector)
{
    int rc;
    size_t written;

    rc = wally_hex_to_bytes(vector->chaincode, vec_chaincode, WALLY_BIP32_CHAIN_CODE_LEN , &written);
    ASSERT_EQ(rc, WALLY_OK);
    ASSERT_EQ(written, (size_t)WALLY_BIP32_CHAIN_CODE_LEN);
    rc = wally_hex_to_bytes(vector->priv, vec_priv, EC_PRIVATE_KEY_LEN, &written);
    ASSERT_EQ(rc, WALLY_OK);
    ASSERT_EQ(written, (size_t)EC_PRIVATE_KEY_LEN);
    rc = wally_hex_to_bytes(vector->pub, vec_pub, EC_PUBLIC_KEY_LEN, &written);
    ASSERT_EQ(rc, WALLY_OK);
    ASSERT_EQ(written, (size_t)EC_PUBLIC_KEY_LEN);
}

TEST_F(TestWally, path_to_hdkey)
{
    int rc;
    struct ext_key *hdkey;
    struct ext_key master_hdkey;
    struct ext_key child_hdkey;
    uint8_t vec_chaincode[WALLY_BIP32_CHAIN_CODE_LEN];
    uint8_t vec_priv[EC_PRIVATE_KEY_LEN];
    uint8_t vec_pub[EC_PUBLIC_KEY_LEN];

    for (size_t i = 0; i < ARRAY_SIZE(bip32_test_vectors); i++) {
        if (i == 0) {
            hdkey = &master_hdkey;
        } else {
            hdkey = &child_hdkey;
        }

        path_test_hex_to_vector(vec_chaincode, vec_priv, vec_pub, &bip32_test_vectors[i]);

        if (i == 0) {
            rc = bip32_key_from_base58(bip32_test_vectors[i].base58Priv, hdkey);
        } else {
            rc = bip32_key_from_parent_path_str(&master_hdkey, bip32_test_vectors[i].path, 0, 0, hdkey);
        }
        ASSERT_EQ(rc, WALLY_OK);
        ASSERT_EQ(memcmp(hdkey->chain_code, vec_chaincode, WALLY_BIP32_CHAIN_CODE_LEN), 0);
        ASSERT_EQ(hdkey->priv_key[0], BIP32_FLAG_KEY_PRIVATE);
        ASSERT_EQ(memcmp(hdkey->priv_key + 1, vec_priv, EC_PRIVATE_KEY_LEN), 0);
        ASSERT_EQ(memcmp(hdkey->pub_key, vec_pub, EC_PUBLIC_KEY_LEN), 0);
    }
}

TEST_F(TestWally, child_from_parent)
{
    int rc;
    struct ext_key hdkeys[ARRAY_SIZE(bip32_test_vectors)];
    uint8_t vec_chaincode[WALLY_BIP32_CHAIN_CODE_LEN];
    uint8_t vec_priv[EC_PRIVATE_KEY_LEN];
    uint8_t vec_pub[EC_PUBLIC_KEY_LEN];

    // m
    path_test_hex_to_vector(vec_chaincode, vec_priv, vec_pub, &bip32_test_vectors[0]);
    rc = bip32_key_from_base58(bip32_test_vectors[0].base58Priv, &hdkeys[0]);
    ASSERT_EQ(rc, WALLY_OK);
    ASSERT_EQ(memcmp(hdkeys[0].chain_code, vec_chaincode, sizeof(vec_chaincode)), 0);
    ASSERT_EQ(hdkeys[0].priv_key[0], BIP32_FLAG_KEY_PRIVATE);
    ASSERT_EQ(memcmp(hdkeys[0].priv_key + 1, vec_priv, sizeof(vec_priv)), 0);
    ASSERT_EQ(memcmp(hdkeys[0].pub_key, vec_pub, sizeof(vec_pub)), 0);

    // depth=1-5
    for (size_t i = 1; i < ARRAY_SIZE(bip32_test_vectors); i++) {
        path_test_hex_to_vector(vec_chaincode, vec_priv, vec_pub, &bip32_test_vectors[i]);
        rc = bip32_key_from_parent(&hdkeys[i - 1], bip32_test_vectors[i].childnum, BIP32_FLAG_KEY_PRIVATE, &hdkeys[i]);
        ASSERT_EQ(rc, WALLY_OK);
        ASSERT_EQ(memcmp(hdkeys[i].chain_code, vec_chaincode, sizeof(vec_chaincode)), 0);
        ASSERT_EQ(hdkeys[i].priv_key[0], BIP32_FLAG_KEY_PRIVATE);
        ASSERT_EQ(memcmp(hdkeys[i].priv_key + 1, vec_priv, sizeof(vec_priv)), 0);
        ASSERT_EQ(memcmp(hdkeys[i].pub_key, vec_pub, sizeof(vec_pub)), 0);
    }
}
