// libwally-coreのテストではなく、libwally-core APIの使い方が正しいかのテスト

#include <stddef.h>

#include <wally_address.h>
#include <wally_crypto.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_descriptor.h>

#include "misc.h"

#include "gtest/gtest.h"
#include "fff.h"

class TestWally: public testing::Test {
    void SetUp() {
        FFF_RESET_HISTORY();
    }
    void TearDown() {
    }

public:
    static void Dump(const uint8_t *data, size_t len) {
        for (size_t i = 0; i < len; i++) {
            printf("%02x", data[i]);
        }
        printf("\n");
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

// BIP-86 Test Vectors
// https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#test-vectors
TEST_F(TestWally, descriptor)
{
    const char DESC_EXT[] = "tr(xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu/86'/0'/0'/0/*)";
    const char DEST_CHG[] = "tr(xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu/86'/0'/0'/1/*)";
    int rc;

    struct wally_descriptor *desc_ext = NULL;
    struct wally_descriptor *desc_chg = NULL;

    char *output = NULL;
    uint32_t child_num = 0;

    // external
    rc = wally_descriptor_parse(
            DESC_EXT,
            NULL,
            WALLY_NETWORK_BITCOIN_MAINNET,
            0,
            &desc_ext
    );
    if (rc != WALLY_OK) {
        printf("error: wally_descriptor_parse fail: %d\n", rc);
        goto cleanup;
    }

    rc = wally_descriptor_to_address(
            desc_ext,
            0,      // variant
            0,      // multi_index
            child_num,    // child_num
            0,      // flags
            &output);
    if (rc != WALLY_OK) {
        printf("error: wally_descriptor_to_address fail: %d\n", rc);
        goto cleanup;
    }
    printf("external: %s\n", output);
    ASSERT_STREQ(output, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr");
    wally_free_string(output);

    rc = wally_descriptor_parse(
            DESC_EXT,
            NULL,
            WALLY_NETWORK_BITCOIN_MAINNET,
            0,
            &desc_ext
    );
    if (rc != WALLY_OK) {
        printf("error: wally_descriptor_parse fail: %d\n", rc);
        goto cleanup;
    }

    // change
    rc = wally_descriptor_parse(
            DEST_CHG,
            NULL,
            WALLY_NETWORK_BITCOIN_MAINNET,
            0,
            &desc_chg
    );
    if (rc != WALLY_OK) {
        printf("error: wally_descriptor_parse(chg) fail: %d\n", rc);
        goto cleanup;
    }

    rc = wally_descriptor_to_address(
            desc_chg,
            0,      // variant
            0,      // multi_index
            child_num,    // child_num
            0,      // flags
            &output);
    if (rc != WALLY_OK) {
        printf("error: wally_descriptor_to_address fail(chg): %d\n", rc);
        goto cleanup;
    }
    printf("internal: %s\n", output);
    ASSERT_STREQ(output, "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7");
    wally_free_string(output);

cleanup:
    if (desc_ext) {
        wally_descriptor_free(desc_ext);
    }
}

// BIP-86 Test Vectors
// https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#test-vectors
TEST_F(TestWally, base58_ext)
{
    int rc;
    struct ext_key hdkey = {0}, childkey = {0};

    // m
    rc = bip32_key_from_base58("xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu", &hdkey);
    ASSERT_EQ(rc, WALLY_OK);
    TestWally::Dump(hdkey.priv_key + 1, 32);
    TestWally::Dump(hdkey.pub_key, 33);

    rc = bip32_key_from_parent_path_str(
        &hdkey,
        "m/86'/0'/0'/0/*", 0,
        BIP32_FLAG_STR_WILDCARD,
        &childkey);
    ASSERT_EQ(rc, WALLY_OK);

    TestWally::Dump(childkey.priv_key + 1, 32);
    TestWally::Dump(childkey.pub_key, 33);
}
