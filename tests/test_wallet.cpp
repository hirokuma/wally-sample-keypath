#include <stddef.h>

#include "gtest/gtest.h"
#include "fff.h"
#include "fakes.h"

extern "C" {
#include "../src/wallet.c"
}

class TestWallet: public testing::Test {
    void SetUp() {
        fakes_init();
    }
    void TearDown() {
    }
};

////////////////////////////////////////////
// wallet_init


// wallet_init
//  - load_wallet
//    - load_mnemonic_file
//      - wally_malloc : fail
TEST_F(TestWallet, wallet_init_load_wallet_fail_mnemonic_malloc)
{
    stat_fake.return_val = 0; // exist file
    wally_malloc_fake.return_val = NULL;

    int rc = wallet_init();
    ASSERT_EQ(rc, 1);
}

// wallet_init
//  - load_wallet
//    - load_mnemonic_file
//      - fopen : fail
TEST_F(TestWallet, wallet_init_load_wallet_fail_mnemonic_fopen)
{
    char dummy_mnemonic[256];

    stat_fake.return_val = 0; // exist file
    wally_malloc_fake.return_val = dummy_mnemonic;
    fopen_fake.return_val = NULL;

    int rc = wallet_init();
    ASSERT_EQ(rc, 1);
}

// wallet_init
//  - load_wallet
//    - load_mnemonic_file
//      - fgets : fail
TEST_F(TestWallet, wallet_init_load_wallet_fail_mnemonic_fgets)
{
    char dummy_mnemonic[256];
    FILE fp = {0};

    stat_fake.return_val = 0; // exist file
    wally_malloc_fake.return_val = dummy_mnemonic;
    fopen_fake.return_val = &fp;
    fgets_fake.return_val = NULL;

    int rc = wallet_init();
    ASSERT_EQ(rc, 1);
    ASSERT_EQ(fclose_fake.call_count, 1UL);
}

// wallet_init
//  - load_wallet
//    - load_mnemonic_file
//      - bip39_mnemonic_validate : fail
TEST_F(TestWallet, wallet_init_load_wallet_fail_mnemonic_validate)
{
    char dummy_mnemonic[256] = {0};
    FILE fp = {0};
    static char dummy_data[10] = "hoge\nhoge"; // strchr(\n)

    stat_fake.return_val = 0; // exist file
    wally_malloc_fake.return_val = dummy_mnemonic;
    fopen_fake.return_val = &fp;
    fgets_fake.custom_fake = [](
        char *s, int n, FILE *stream
    ) -> char* {
        strcpy(s, dummy_data);
        return (char *)dummy_data;
    };
    bip39_mnemonic_validate_fake.return_val = WALLY_EINVAL;

    int rc = wallet_init();
    ASSERT_EQ(rc, 1);
    ASSERT_EQ(fclose_fake.call_count, 1UL);
}

// wallet_init
//  - load_wallet
//    - load_index_file
//      - fopen : fail
TEST_F(TestWallet, wallet_init_load_wallet_fail_index_fopen)
{
    char dummy_mnemonic[256] = {0};
    FILE fp = {0};
    FILE* open_retval[2] = { &fp, NULL };
    static char dummy_data[10] = "hogehoge";

    stat_fake.return_val = 0; // exist file
    wally_malloc_fake.return_val = dummy_mnemonic;
    SET_RETURN_SEQ(fopen, open_retval, ARRAY_SIZE(open_retval));
    fgets_fake.custom_fake = [](
        char *s, int n, FILE *stream
    ) -> char* {
        strcpy(s, dummy_data);
        return (char *)dummy_data;
    };
    bip39_mnemonic_validate_fake.return_val = 0;

    int rc = wallet_init();
    ASSERT_EQ(rc, 1);
    ASSERT_EQ(fclose_fake.call_count, 1UL);
}

// wallet_init
//  - load_wallet
//    - load_index_file
//      - fscanf : fail
TEST_F(TestWallet, wallet_init_load_wallet_fail_index_fscanf)
{
    char dummy_mnemonic[256] = {0};
    FILE fp = {0};
    static char dummy_data[10] = "hogehoge";

    stat_fake.return_val = 0; // exist file
    wally_malloc_fake.return_val = dummy_mnemonic;
    fopen_fake.return_val = &fp;
    fgets_fake.custom_fake = [](
        char *s, int n, FILE *stream
    ) -> char* {
        strcpy(s, dummy_data);
        return (char *)dummy_data;
    };
    bip39_mnemonic_validate_fake.return_val = 0;

    // load_index_file
    fscanf_fake.return_val = 1;

    int rc = wallet_init();
    ASSERT_EQ(rc, 1);
    ASSERT_EQ(fclose_fake.call_count, 2UL);
}

// wallet_init
//  - create_wallet
//    - create_mnemonic_file
//      - fill_random : fail
TEST_F(TestWallet, wallet_init_create_wallet_fail_mnemonic_random)
{
    stat_fake.return_val = 1; // not exist file
    fill_random_fake.return_val = 1;

    int rc = wallet_init();
    ASSERT_EQ(rc, 1);
}

// wallet_init
//  - create_wallet
//    - create_mnemonic_file
//      - bip39_mnemonic_from_bytes : fail
TEST_F(TestWallet, wallet_init_create_wallet_fail_mnemonic)
{
    stat_fake.return_val = 1; // not exist file
    fill_random_fake.return_val = 0;
    bip39_mnemonic_from_bytes_fake.return_val = WALLY_EINVAL;

    int rc = wallet_init();
    ASSERT_EQ(rc, 1);
}

// wallet_init
//  - create_wallet
//    - create_mnemonic_file
//      - fopen : fail
TEST_F(TestWallet, wallet_init_create_wallet_fail_fopen)
{
    stat_fake.return_val = 1; // not exist file
    fill_random_fake.return_val = 0;
    bip39_mnemonic_from_bytes_fake.return_val = 0;
    fopen_fake.return_val = NULL;

    int rc = wallet_init();
    ASSERT_EQ(rc, 1);
}

// wallet_init
//  - create_wallet
//    - save_index_file
//      - fopen : fail
TEST_F(TestWallet, wallet_init_create_wallet_fail_index_fopen)
{
    FILE fp = {0};
    FILE* open_retval[2] = { &fp, NULL };

    stat_fake.return_val = 1; // not exist file
    fill_random_fake.return_val = 0;
    bip39_mnemonic_from_bytes_fake.return_val = 0;
    SET_RETURN_SEQ(fopen, open_retval, ARRAY_SIZE(open_retval));

    int rc = wallet_init();
    ASSERT_EQ(rc, 1);
}

// wallet_init
//  - load_wallet
//  - create_masterkey
//    - bip39_mnemonic_to_seed : fail
TEST_F(TestWallet, wallet_init_create_masterkey_fail_to_seed)
{
    char dummy_mnemonic[256] = {0};
    FILE fp = {0};
    static char dummy_data[10] = "hogehoge";

    stat_fake.return_val = 0; // exist file
    wally_malloc_fake.return_val = dummy_mnemonic;
    fopen_fake.return_val = &fp;
    fgets_fake.custom_fake = [](
        char *s, int n, FILE *stream
    ) -> char* {
        strcpy(s, dummy_data);
        return (char *)dummy_data;
    };
    bip39_mnemonic_validate_fake.return_val = 0;

    // load_index_file
    fscanf_fake.custom_fake = [](
        FILE* fp, const char* fmt, va_list ap
    ) -> int {
        uint32_t *p1 = va_arg(ap, uint32_t*);
        *p1 = 123;
        uint32_t *p2 = va_arg(ap, uint32_t*);
        *p2 = 456;
        return 2;
    };

    // create_masterkey
    bip39_mnemonic_to_seed_fake.return_val = WALLY_ERROR;
    //

    int rc = wallet_init();
    ASSERT_EQ(rc, 1);
}

// wallet_init
//  - load_wallet
//  - create_masterkey
//    - bip39_mnemonic_to_seed : fail
TEST_F(TestWallet, wallet_init_create_masterkey_fail_to_seed_len)
{
    char dummy_mnemonic[256] = {0};
    FILE fp = {0};
    static char dummy_data[10] = "hogehoge";

    stat_fake.return_val = 0; // exist file
    wally_malloc_fake.return_val = dummy_mnemonic;
    fopen_fake.return_val = &fp;
    fgets_fake.custom_fake = [](
        char *s, int n, FILE *stream
    ) -> char* {
        strcpy(s, dummy_data);
        return (char *)dummy_data;
    };
    bip39_mnemonic_validate_fake.return_val = 0;

    // load_index_file
    fscanf_fake.custom_fake = [](
        FILE* fp, const char* fmt, va_list ap
    ) -> int {
        uint32_t *p1 = va_arg(ap, uint32_t*);
        *p1 = 123;
        uint32_t *p2 = va_arg(ap, uint32_t*);
        *p2 = 456;
        return 2;
    };

    // create_masterkey
    bip39_mnemonic_to_seed_fake.custom_fake = [](
        const char *mnemonic,
        const char *passphrase,
        unsigned char *bytes_out,
        size_t len,
        size_t *written
    ) -> int {
        *written = 10;
        return WALLY_OK;
    };
    //

    int rc = wallet_init();
    ASSERT_EQ(rc, 1);
}

// wallet_init
//  - load_wallet
//  - create_masterkey
//    - bip32_key_from_seed : fail
TEST_F(TestWallet, wallet_init_create_masterkey_fail_from_seed)
{
    char dummy_mnemonic[256] = {0};
    FILE fp = {0};
    static char dummy_data[10] = "hogehoge";

    stat_fake.return_val = 0; // exist file

    // load_wallet
    wally_malloc_fake.return_val = dummy_mnemonic;
    fopen_fake.return_val = &fp;
    fgets_fake.custom_fake = [](
        char *s, int n, FILE *stream
    ) -> char* {
        strcpy(s, dummy_data);
        return (char *)dummy_data;
    };
    bip39_mnemonic_validate_fake.return_val = 0;

    // load_index_file
    fscanf_fake.custom_fake = [](
        FILE* fp, const char* fmt, va_list ap
    ) -> int {
        uint32_t *p1 = va_arg(ap, uint32_t*);
        *p1 = 123;
        uint32_t *p2 = va_arg(ap, uint32_t*);
        *p2 = 456;
        return 2;
    };

    // create_masterkey
    bip39_mnemonic_to_seed_fake.custom_fake = [](
        const char *mnemonic,
        const char *passphrase,
        unsigned char *bytes_out,
        size_t len,
        size_t *written
    ) -> int {
        *written = BIP39_SEED_LEN_512;
        return WALLY_OK;
    };
    bip32_key_from_seed_fake.return_val = WALLY_ERROR;
    //

    int rc = wallet_init();
    ASSERT_EQ(rc, 1);
}

// wallet_init
//  - load_wallet
//  - create_masterkey
//  - bip32_key_from_parent_path_str : fail
TEST_F(TestWallet, wallet_init_path_str1)
{
    char dummy_mnemonic[256] = {0};
    FILE fp = {0};
    static char dummy_data[10] = "hogehoge";

    stat_fake.return_val = 0; // exist file

    // load_wallet
    wally_malloc_fake.return_val = dummy_mnemonic;
    fopen_fake.return_val = &fp;
    fgets_fake.custom_fake = [](
        char *s, int n, FILE *stream
    ) -> char* {
        strcpy(s, dummy_data);
        return (char *)dummy_data;
    };
    bip39_mnemonic_validate_fake.return_val = 0;

    // load_index_file
    fscanf_fake.custom_fake = [](
        FILE* fp, const char* fmt, va_list ap
    ) -> int {
        uint32_t *p1 = va_arg(ap, uint32_t*);
        *p1 = 123;
        uint32_t *p2 = va_arg(ap, uint32_t*);
        *p2 = 456;
        return 2;
    };

    // create_masterkey
    bip39_mnemonic_to_seed_fake.custom_fake = [](
        const char *mnemonic,
        const char *passphrase,
        unsigned char *bytes_out,
        size_t len,
        size_t *written
    ) -> int {
        *written = BIP39_SEED_LEN_512;
        return WALLY_OK;
    };
    bip32_key_from_seed_fake.return_val = WALLY_OK;

    //
    auto path_str1 = [](
        const struct ext_key *hdkey,
        const char *path_str,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        return WALLY_ERROR;
    };
    int (*path_str_seq[])(
        const struct ext_key *hdkey,
        const char *path_str,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) = { path_str1 };
    SET_CUSTOM_FAKE_SEQ(bip32_key_from_parent_path_str, path_str_seq, ARRAY_SIZE(path_str_seq));

    int rc = wallet_init();
    ASSERT_EQ(rc, 1);
    ASSERT_EQ(bip32_key_from_parent_path_str_fake.call_count, 1UL);
}

// wallet_init
//  - load_wallet
//  - create_masterkey
//  - bip32_key_from_parent_path_str
//  - bip32_key_from_parent_path_str : fail
TEST_F(TestWallet, wallet_init_path_str2)
{
    char dummy_mnemonic[256] = {0};
    FILE fp = {0};
    static char dummy_data[10] = "hogehoge";

    stat_fake.return_val = 0; // exist file

    // load_wallet
    wally_malloc_fake.return_val = dummy_mnemonic;
    fopen_fake.return_val = &fp;
    fgets_fake.custom_fake = [](
        char *s, int n, FILE *stream
    ) -> char* {
        strcpy(s, dummy_data);
        return (char *)dummy_data;
    };
    bip39_mnemonic_validate_fake.return_val = 0;

    // load_index_file
    fscanf_fake.custom_fake = [](
        FILE* fp, const char* fmt, va_list ap
    ) -> int {
        uint32_t *p1 = va_arg(ap, uint32_t*);
        *p1 = 123;
        uint32_t *p2 = va_arg(ap, uint32_t*);
        *p2 = 456;
        return 2;
    };

    // create_masterkey
    bip39_mnemonic_to_seed_fake.custom_fake = [](
        const char *mnemonic,
        const char *passphrase,
        unsigned char *bytes_out,
        size_t len,
        size_t *written
    ) -> int {
        *written = BIP39_SEED_LEN_512;
        return WALLY_OK;
    };
    bip32_key_from_seed_fake.return_val = WALLY_OK;

    //
    auto path_str1 = [](
        const struct ext_key *hdkey,
        const char *path_str,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        return WALLY_OK;
    };
    auto path_str2 = [](
        const struct ext_key *hdkey,
        const char *path_str,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        return WALLY_ERROR;
    };
    int (*path_str_seq[])(
        const struct ext_key *hdkey,
        const char *path_str,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) = { path_str1, path_str2 };
    SET_CUSTOM_FAKE_SEQ(bip32_key_from_parent_path_str, path_str_seq, ARRAY_SIZE(path_str_seq));

    int rc = wallet_init();
    ASSERT_EQ(rc, 1);
    ASSERT_EQ(bip32_key_from_parent_path_str_fake.call_count, 2UL);
}

// wallet_init
//  - load_wallet
//  - create_masterkey
//  - bip32_key_from_parent_path_str
//  - bip32_key_from_parent_path_str
TEST_F(TestWallet, wallet_init_ok_load)
{
    char dummy_mnemonic[256] = {0};
    FILE fp = {0};
    static char dummy_data[10] = "hogehoge";

    stat_fake.return_val = 0; // exist file

    // load_wallet
    wally_malloc_fake.return_val = dummy_mnemonic;
    fopen_fake.return_val = &fp;
    fgets_fake.custom_fake = [](
        char *s, int n, FILE *stream
    ) -> char* {
        strcpy(s, dummy_data);
        return (char *)dummy_data;
    };
    bip39_mnemonic_validate_fake.return_val = 0;

    // load_index_file
    fscanf_fake.custom_fake = [](
        FILE* fp, const char* fmt, va_list ap
    ) -> int {
        uint32_t *p1 = va_arg(ap, uint32_t*);
        *p1 = 123;
        uint32_t *p2 = va_arg(ap, uint32_t*);
        *p2 = 456;
        return 2;
    };

    // create_masterkey
    bip39_mnemonic_to_seed_fake.custom_fake = [](
        const char *mnemonic,
        const char *passphrase,
        unsigned char *bytes_out,
        size_t len,
        size_t *written
    ) -> int {
        *written = BIP39_SEED_LEN_512;
        return WALLY_OK;
    };
    bip32_key_from_seed_fake.return_val = WALLY_OK;

    //
    static struct ext_key dummy1, dummy2;
    fakes_data(&dummy1, sizeof(struct ext_key));
    fakes_data(&dummy2, sizeof(struct ext_key));
    auto path_str1 = [](
        const struct ext_key *hdkey,
        const char *path_str,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        memcpy(output, &dummy1, sizeof(struct ext_key));
        return WALLY_OK;
    };
    auto path_str2 = [](
        const struct ext_key *hdkey,
        const char *path_str,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        memcpy(output, &dummy2, sizeof(struct ext_key));
        return WALLY_OK;
    };
    int (*path_str_seq[])(
        const struct ext_key *hdkey,
        const char *path_str,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) = { path_str1, path_str2 };
    SET_CUSTOM_FAKE_SEQ(bip32_key_from_parent_path_str, path_str_seq, ARRAY_SIZE(path_str_seq));

    int rc = wallet_init();
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(dummy_mnemonic, dummy_data);
    ASSERT_EQ(opened_wallet.ws[WALLET_KEYS_EXTN].next_index, 123U);
    ASSERT_EQ(opened_wallet.ws[WALLET_KEYS_INTR].next_index, 456U);
    ASSERT_EQ(memcmp(&opened_wallet.ws[WALLET_KEYS_EXTN].hdkey, &dummy1, sizeof(struct ext_key)), 0);
    ASSERT_EQ(memcmp(&opened_wallet.ws[WALLET_KEYS_INTR].hdkey, &dummy2, sizeof(struct ext_key)), 0);
}

// wallet_init
//  - create_wallet
//  - create_masterkey
//  - bip32_key_from_parent_path_str
//  - bip32_key_from_parent_path_str
TEST_F(TestWallet, wallet_init_ok_create)
{
    static char dummy_mnemonic[256] = {0};
    FILE fp = {0};
    static char dummy_data[10] = "hogehoge";

    stat_fake.return_val = -1; // not exist file

    // create_wallet
    fill_random_fake.return_val = 0;
    bip39_mnemonic_from_bytes_fake.custom_fake = [](
        const struct words *w,
        const unsigned char *bytes,
        size_t bytes_len,
        char **output)
    -> int {
        strcpy(dummy_mnemonic, dummy_data);
        *output = dummy_mnemonic;
        return WALLY_OK;
    };
    fopen_fake.return_val = &fp;

    // create_masterkey
    bip39_mnemonic_to_seed_fake.custom_fake = [](
        const char *mnemonic,
        const char *passphrase,
        unsigned char *bytes_out,
        size_t len,
        size_t *written
    ) -> int {
        *written = BIP39_SEED_LEN_512;
        return WALLY_OK;
    };
    bip32_key_from_seed_fake.return_val = WALLY_OK;

    //
    static struct ext_key dummy1, dummy2;
    fakes_data(&dummy1, sizeof(struct ext_key));
    fakes_data(&dummy2, sizeof(struct ext_key));
    auto path_str1 = [](
        const struct ext_key *hdkey,
        const char *path_str,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        memcpy(output, &dummy1, sizeof(struct ext_key));
        return WALLY_OK;
    };
    auto path_str2 = [](
        const struct ext_key *hdkey,
        const char *path_str,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        memcpy(output, &dummy2, sizeof(struct ext_key));
        return WALLY_OK;
    };
    int (*path_str_seq[])(
        const struct ext_key *hdkey,
        const char *path_str,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) = { path_str1, path_str2 };
    SET_CUSTOM_FAKE_SEQ(bip32_key_from_parent_path_str, path_str_seq, ARRAY_SIZE(path_str_seq));

    int rc = wallet_init();
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(dummy_mnemonic, dummy_data);
    ASSERT_EQ(opened_wallet.ws[WALLET_KEYS_EXTN].next_index, 0U);
    ASSERT_EQ(opened_wallet.ws[WALLET_KEYS_INTR].next_index, 0U);
    ASSERT_EQ(memcmp(&opened_wallet.ws[WALLET_KEYS_EXTN].hdkey, &dummy1, sizeof(struct ext_key)), 0);
    ASSERT_EQ(memcmp(&opened_wallet.ws[WALLET_KEYS_INTR].hdkey, &dummy2, sizeof(struct ext_key)), 0);
}

////////////////////////////////////////////
// wallet_get_address

// wallet_get_address(extn)
//  - get_addr_hdkey
//    - chg_hdkey->depth != 4
TEST_F(TestWallet, wallet_get_address_extn_get_hdkey_hdkey_depth)
{
    struct wallet_address wa = {
        .keys_type = WALLET_KEYS_EXTN,
        .index = 12,
    };

    // get_addr_hdkey
    opened_wallet.ws[wa.keys_type].next_index = 13; // != wa.index
    opened_wallet.ws[wa.keys_type].hdkey.depth = 3; // not 4

    int done = 0;
    int rc = wallet_get_address(&wa, &done);
    ASSERT_EQ(rc, 1);
}

// wallet_get_address(extn)
//  - get_addr_hdkey
//    - bip32_key_from_parent : fail
TEST_F(TestWallet, wallet_get_address_extn_get_hdkey_from_parent)
{
    struct wallet_address wa = {
        .keys_type = WALLET_KEYS_EXTN,
        .index = 12,
    };

    // get_addr_hdkey
    opened_wallet.ws[wa.keys_type].next_index = 13; // != wa.index
    opened_wallet.ws[wa.keys_type].hdkey.depth = 4;
    bip32_key_from_parent_fake.return_val = WALLY_ERROR;

    int done = 0;
    int rc = wallet_get_address(&wa, &done);
    ASSERT_EQ(rc, 1);
}

// wallet_get_address(extn)
//  - get_addr_hdkey
//    - hdkey->priv_key[0] != BIP32_FLAG_KEY_PRIVATE
TEST_F(TestWallet, wallet_get_address_extn_get_hdkey_priv_key)
{
    struct wallet_address wa = {
        .keys_type = WALLET_KEYS_EXTN,
        .index = 12,
    };

    // get_addr_hdkey
    opened_wallet.ws[wa.keys_type].next_index = 13; // != wa.index
    opened_wallet.ws[wa.keys_type].hdkey.depth = 4;
    bip32_key_from_parent_fake.custom_fake = [](
        const struct ext_key *hdkey,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        output->priv_key[0] = BIP32_FLAG_KEY_PUBLIC;
        return WALLY_OK;
    };

    int done = 0;
    int rc = wallet_get_address(&wa, &done);
    ASSERT_EQ(rc, 1);
}

// wallet_get_address(extn)
//  - get_addr_hdkey
//  - get_address
//    - addr_hdkey->depth != 5
TEST_F(TestWallet, wallet_get_address_extn_get_addr_depth)
{
    struct wallet_address wa = {
        .keys_type = WALLET_KEYS_EXTN,
        .index = 12,
    };

    // get_addr_hdkey
    opened_wallet.ws[wa.keys_type].next_index = 13; // != wa.index
    opened_wallet.ws[wa.keys_type].hdkey.depth = 4;
    bip32_key_from_parent_fake.custom_fake = [](
        const struct ext_key *hdkey,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        output->priv_key[0] = BIP32_FLAG_KEY_PRIVATE;
        output->depth = 4; // != 5
        return WALLY_OK;
    };

    // get_address

    int done = 0;
    int rc = wallet_get_address(&wa, &done);
    ASSERT_EQ(rc, 1);
}

// wallet_get_address(extn)
//  - get_addr_hdkey
//  - get_address
//    - get_scriptpubkey_from_hdkey
//      - wally_scriptpubkey_p2tr_from_bytes : fail
TEST_F(TestWallet, wallet_get_address_extn_get_addr_from_hdkey_from_bytes)
{
    struct wallet_address wa = {
        .keys_type = WALLET_KEYS_EXTN,
        .index = 12,
    };

    // get_addr_hdkey
    opened_wallet.ws[wa.keys_type].next_index = 13; // != wa.index
    opened_wallet.ws[wa.keys_type].hdkey.depth = 4;
    bip32_key_from_parent_fake.custom_fake = [](
        const struct ext_key *hdkey,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        output->priv_key[0] = BIP32_FLAG_KEY_PRIVATE;
        output->depth = 5;
        return WALLY_OK;
    };

    // get_address
    //  - get_scriptpubkey_from_hdkey
    wally_scriptpubkey_p2tr_from_bytes_fake.return_val = WALLY_ERROR;

    int done = 0;
    int rc = wallet_get_address(&wa, &done);
    ASSERT_EQ(rc, 1);
}

// wallet_get_address(extn)
//  - get_addr_hdkey
//  - get_address
//    - get_scriptpubkey_from_hdkey
//      - wally_scriptpubkey_p2tr_from_bytes : written > *len
TEST_F(TestWallet, wallet_get_address_extn_get_addr_from_hdkey_from_bytes_len)
{
    struct wallet_address wa = {
        .keys_type = WALLET_KEYS_EXTN,
        .index = 12,
    };

    // get_addr_hdkey
    opened_wallet.ws[wa.keys_type].next_index = 13; // != wa.index
    opened_wallet.ws[wa.keys_type].hdkey.depth = 4;
    bip32_key_from_parent_fake.custom_fake = [](
        const struct ext_key *hdkey,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        output->priv_key[0] = BIP32_FLAG_KEY_PRIVATE;
        output->depth = 5;
        return WALLY_OK;
    };

    // get_address
    //  - get_scriptpubkey_from_hdkey
    wally_scriptpubkey_p2tr_from_bytes_fake.custom_fake = [](
        const unsigned char *bytes,
        size_t bytes_len,
        uint32_t flags,
        unsigned char *bytes_out,
        size_t len,
        size_t *written
    ) -> int {
        *written = len + 1; // written > *len
        return WALLY_OK;
    };

    int done = 0;
    int rc = wallet_get_address(&wa, &done);
    ASSERT_EQ(rc, 1);
}

// wallet_get_address(extn)
//  - get_addr_hdkey
//  - get_address
//    - get_scriptpubkey_from_hdkey
//      - wally_scriptpubkey_p2tr_from_bytes
//        - written < WALLY_SCRIPTPUBKEY_P2TR_LEN
TEST_F(TestWallet, wallet_get_address_extn_get_addr_written)
{
    struct wallet_address wa = {
        .keys_type = WALLET_KEYS_EXTN,
        .index = 12,
    };

    // get_addr_hdkey
    opened_wallet.ws[wa.keys_type].next_index = 13; // != wa.index
    opened_wallet.ws[wa.keys_type].hdkey.depth = 4;
    bip32_key_from_parent_fake.custom_fake = [](
        const struct ext_key *hdkey,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        output->priv_key[0] = BIP32_FLAG_KEY_PRIVATE;
        output->depth = 5;
        return WALLY_OK;
    };

    // get_address
    //  - get_scriptpubkey_from_hdkey
    wally_scriptpubkey_p2tr_from_bytes_fake.custom_fake = [](
        const unsigned char *bytes,
        size_t bytes_len,
        uint32_t flags,
        unsigned char *bytes_out,
        size_t len,
        size_t *written
    ) -> int {
        *written = len - 1; // != WALLY_SCRIPTPUBKEY_P2TR_LEN
        return WALLY_OK;
    };

    int done = 0;
    int rc = wallet_get_address(&wa, &done);
    ASSERT_EQ(rc, 1);
}

// wallet_get_address(extn)
//  - get_addr_hdkey
//  - get_address
//    - address_from_scriptpubkey : fail
TEST_F(TestWallet, wallet_get_address_extn_get_addr_from_addr_from)
{
    struct wallet_address wa = {
        .keys_type = WALLET_KEYS_EXTN,
        .index = 12,
    };

    // get_addr_hdkey
    opened_wallet.ws[wa.keys_type].next_index = 13; // != wa.index
    opened_wallet.ws[wa.keys_type].hdkey.depth = 4;
    bip32_key_from_parent_fake.custom_fake = [](
        const struct ext_key *hdkey,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        output->priv_key[0] = BIP32_FLAG_KEY_PRIVATE;
        output->depth = 5;
        return WALLY_OK;
    };

    // get_address
    //  - get_scriptpubkey_from_hdkey
    wally_scriptpubkey_p2tr_from_bytes_fake.custom_fake = [](
        const unsigned char *bytes,
        size_t bytes_len,
        uint32_t flags,
        unsigned char *bytes_out,
        size_t len,
        size_t *written
    ) -> int {
        *written = len;
        return WALLY_OK;
    };
    address_from_scriptpubkey_fake.return_val = 1;

    int done = 0;
    int rc = wallet_get_address(&wa, &done);
    ASSERT_EQ(rc, 1);
}

// wallet_get_address(extn)
//  - get_addr_hdkey
//  - get_address
//    - address_from_scriptpubkey
TEST_F(TestWallet, wallet_get_address_extn_ok)
{
    struct wallet_address wa = {
        .keys_type = WALLET_KEYS_EXTN,
        .index = 12,
    };

    // get_addr_hdkey
    opened_wallet.ws[wa.keys_type].next_index = 13; // != wa.index
    opened_wallet.ws[wa.keys_type].hdkey.depth = 4;
    bip32_key_from_parent_fake.custom_fake = [](
        const struct ext_key *hdkey,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        output->priv_key[0] = BIP32_FLAG_KEY_PRIVATE;
        output->depth = 5;
        return WALLY_OK;
    };

    // get_address
    //  - get_scriptpubkey_from_hdkey
    wally_scriptpubkey_p2tr_from_bytes_fake.custom_fake = [](
        const unsigned char *bytes,
        size_t bytes_len,
        uint32_t flags,
        unsigned char *bytes_out,
        size_t len,
        size_t *written
    ) -> int {
        *written = len;
        return WALLY_OK;
    };
    address_from_scriptpubkey_fake.return_val = 0;

    int done = 0;
    int rc = wallet_get_address(&wa, &done);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(done, 0);
    ASSERT_EQ(wa.keys_type, WALLET_KEYS_EXTN);
    ASSERT_EQ(wa.index, 13UL);
}

// wallet_get_address(extn -> intr)
//  - get_addr_hdkey
//  - get_address
//    - address_from_scriptpubkey
TEST_F(TestWallet, wallet_get_address_extn_to_intr_ok)
{
    struct wallet_address wa = {
        .keys_type = WALLET_KEYS_EXTN,
        .index = 12,
    };

    // get_addr_hdkey
    opened_wallet.ws[WALLET_KEYS_EXTN].next_index = 12; // == wa.index
    opened_wallet.ws[WALLET_KEYS_INTR].next_index = 12; // != 0
    opened_wallet.ws[WALLET_KEYS_EXTN].hdkey.depth = 4;
    opened_wallet.ws[WALLET_KEYS_INTR].hdkey.depth = 4;
    bip32_key_from_parent_fake.custom_fake = [](
        const struct ext_key *hdkey,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        output->priv_key[0] = BIP32_FLAG_KEY_PRIVATE;
        output->depth = 5;
        return WALLY_OK;
    };

    // get_address
    //  - get_scriptpubkey_from_hdkey
    wally_scriptpubkey_p2tr_from_bytes_fake.custom_fake = [](
        const unsigned char *bytes,
        size_t bytes_len,
        uint32_t flags,
        unsigned char *bytes_out,
        size_t len,
        size_t *written
    ) -> int {
        *written = len;
        return WALLY_OK;
    };
    address_from_scriptpubkey_fake.return_val = 0;

    int done = 0;
    int rc = wallet_get_address(&wa, &done);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(done, 0);
    ASSERT_EQ(wa.keys_type, WALLET_KEYS_INTR);
    ASSERT_EQ(wa.index, 1UL);
}

// wallet_get_address(intr)
//  - get_addr_hdkey
//  - get_address
//    - address_from_scriptpubkey
TEST_F(TestWallet, wallet_get_address_intr_ok)
{
    struct wallet_address wa = {
        .keys_type = WALLET_KEYS_INTR,
        .index = 123,
    };

    // get_addr_hdkey
    opened_wallet.ws[wa.keys_type].next_index = 124; // != wa.index
    opened_wallet.ws[wa.keys_type].hdkey.depth = 4;
    bip32_key_from_parent_fake.custom_fake = [](
        const struct ext_key *hdkey,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        output->priv_key[0] = BIP32_FLAG_KEY_PRIVATE;
        output->depth = 5;
        return WALLY_OK;
    };

    // get_address
    //  - get_scriptpubkey_from_hdkey
    wally_scriptpubkey_p2tr_from_bytes_fake.custom_fake = [](
        const unsigned char *bytes,
        size_t bytes_len,
        uint32_t flags,
        unsigned char *bytes_out,
        size_t len,
        size_t *written
    ) -> int {
        *written = len;
        return WALLY_OK;
    };
    address_from_scriptpubkey_fake.return_val = 0;

    int done = 0;
    int rc = wallet_get_address(&wa, &done);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(done, 0);
    ASSERT_EQ(wa.keys_type, WALLET_KEYS_INTR);
    ASSERT_EQ(wa.index, 124UL);
}

// wallet_get_address(intr)
//  - get_addr_hdkey
//  - get_address
//    - address_from_scriptpubkey
TEST_F(TestWallet, wallet_get_address_intr_done_ok)
{
    struct wallet_address wa = {
        .keys_type = WALLET_KEYS_INTR,
        .index = 123,
    };

    // get_addr_hdkey
    opened_wallet.ws[wa.keys_type].next_index = 123; // == wa.index
    opened_wallet.ws[wa.keys_type].hdkey.depth = 4;
    bip32_key_from_parent_fake.custom_fake = [](
        const struct ext_key *hdkey,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        output->priv_key[0] = BIP32_FLAG_KEY_PRIVATE;
        output->depth = 5;
        return WALLY_OK;
    };

    // get_address
    //  - get_scriptpubkey_from_hdkey
    wally_scriptpubkey_p2tr_from_bytes_fake.custom_fake = [](
        const unsigned char *bytes,
        size_t bytes_len,
        uint32_t flags,
        unsigned char *bytes_out,
        size_t len,
        size_t *written
    ) -> int {
        *written = len;
        return WALLY_OK;
    };
    address_from_scriptpubkey_fake.return_val = 0;

    int done = 0;
    int rc = wallet_get_address(&wa, &done);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(done, 1);
}

////////////////////////////////////////////
// wallet_new_extr_address

// wallet_new_extr_address
//  - new_address
//    - get_addr_hdkey
//      - chg_hdkey->depth != 4
TEST_F(TestWallet, wallet_new_extr_address_hdkey_depth)
{
    // &opened_wallet.ws[WALLET_KEYS_EXTN]
    opened_wallet.ws[WALLET_KEYS_EXTN].hdkey.depth = 3; // not 4

    char addr[ADDRESS_STR_MAX];
    int rc = wallet_new_extr_address(addr);
    ASSERT_EQ(rc, 1);
}

// wallet_new_extr_address
//  - new_address
//    - get_addr_hdkey
//    - get_address
//      - addr_hdkey->depth != 5
TEST_F(TestWallet, wallet_new_extr_address_address_depth)
{
    opened_wallet.ws[WALLET_KEYS_EXTN].hdkey.depth = 4;
    bip32_key_from_parent_fake.custom_fake = [](
        const struct ext_key *hdkey,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        output->priv_key[0] = BIP32_FLAG_KEY_PRIVATE;
        output->depth = 4; // != 5
        return WALLY_OK;
    };

    char addr[ADDRESS_STR_MAX];
    int rc = wallet_new_extr_address(addr);
    ASSERT_EQ(rc, 1);
}

// wallet_new_extr_address
//  - new_address
//    - get_addr_hdkey
//    - get_address
//    - save_index_file
TEST_F(TestWallet, wallet_new_extr_address_save_fopen)
{
    opened_wallet.ws[WALLET_KEYS_EXTN].hdkey.depth = 4;
    bip32_key_from_parent_fake.custom_fake = [](
        const struct ext_key *hdkey,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        output->priv_key[0] = BIP32_FLAG_KEY_PRIVATE;
        output->depth = 5;
        return WALLY_OK;
    };

    // get_address
    //  - get_scriptpubkey_from_hdkey
    wally_scriptpubkey_p2tr_from_bytes_fake.custom_fake = [](
        const unsigned char *bytes,
        size_t bytes_len,
        uint32_t flags,
        unsigned char *bytes_out,
        size_t len,
        size_t *written
    ) -> int {
        *written = len;
        return WALLY_OK;
    };
    address_from_scriptpubkey_fake.return_val = 0;

    // save_index_file
    fopen_fake.return_val = NULL;

    char addr[ADDRESS_STR_MAX];
    int rc = wallet_new_extr_address(addr);
    ASSERT_EQ(rc, 1);
}

// wallet_new_extr_address
//  - new_address
//    - get_addr_hdkey
//    - get_address
//    - save_index_file
TEST_F(TestWallet, wallet_new_extr_address)
{
    opened_wallet.ws[WALLET_KEYS_EXTN].hdkey.depth = 4;
    bip32_key_from_parent_fake.custom_fake = [](
        const struct ext_key *hdkey,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        output->priv_key[0] = BIP32_FLAG_KEY_PRIVATE;
        output->depth = 5;
        return WALLY_OK;
    };

    // get_address
    //  - get_scriptpubkey_from_hdkey
    wally_scriptpubkey_p2tr_from_bytes_fake.custom_fake = [](
        const unsigned char *bytes,
        size_t bytes_len,
        uint32_t flags,
        unsigned char *bytes_out,
        size_t len,
        size_t *written
    ) -> int {
        *written = len;
        return WALLY_OK;
    };
    address_from_scriptpubkey_fake.return_val = 0;

    // save_index_file
    fopen_fake.return_val = (FILE *)1;

    char addr[ADDRESS_STR_MAX];
    int rc = wallet_new_extr_address(addr);
    ASSERT_EQ(rc, 0);
}

////////////////////////////////////////////
// wallet_new_intr_address

// wallet_new_intr_address
//  - new_address
//    - get_addr_hdkey
//      - chg_hdkey->depth != 4
TEST_F(TestWallet, wallet_new_intr_address_hdkey_depth)
{
    opened_wallet.ws[WALLET_KEYS_INTR].hdkey.depth = 3; // not 4

    char addr[ADDRESS_STR_MAX];
    int rc = wallet_new_intr_address(addr, NULL, NULL);
    ASSERT_EQ(rc, 1);
}

// wallet_new_intr_address
//  - new_address
//    - get_addr_hdkey
//    - get_address
//      - addr_hdkey->depth != 5
TEST_F(TestWallet, wallet_new_intr_address_address_depth)
{
    opened_wallet.ws[WALLET_KEYS_INTR].hdkey.depth = 4;
    bip32_key_from_parent_fake.custom_fake = [](
        const struct ext_key *hdkey,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        output->priv_key[0] = BIP32_FLAG_KEY_PRIVATE;
        output->depth = 4; // != 5
        return WALLY_OK;
    };

    char addr[ADDRESS_STR_MAX];
    int rc = wallet_new_intr_address(addr, NULL, NULL);
    ASSERT_EQ(rc, 1);
}

// wallet_new_intr_address
//  - new_address
//    - get_addr_hdkey
//    - get_address
//    - save_index_file
TEST_F(TestWallet, wallet_new_intr_address_save_fopen)
{
    opened_wallet.ws[WALLET_KEYS_INTR].hdkey.depth = 4;
    bip32_key_from_parent_fake.custom_fake = [](
        const struct ext_key *hdkey,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        output->priv_key[0] = BIP32_FLAG_KEY_PRIVATE;
        output->depth = 5;
        return WALLY_OK;
    };

    // get_address
    //  - get_scriptpubkey_from_hdkey
    wally_scriptpubkey_p2tr_from_bytes_fake.custom_fake = [](
        const unsigned char *bytes,
        size_t bytes_len,
        uint32_t flags,
        unsigned char *bytes_out,
        size_t len,
        size_t *written
    ) -> int {
        *written = len;
        return WALLY_OK;
    };
    address_from_scriptpubkey_fake.return_val = 0;

    // save_index_file
    fopen_fake.return_val = NULL;

    char addr[ADDRESS_STR_MAX];
    int rc = wallet_new_intr_address(addr, NULL, NULL);
    ASSERT_EQ(rc, 1);
}

// wallet_new_intr_address
//  - new_address
//    - get_addr_hdkey
//    - get_address
//    - save_index_file
TEST_F(TestWallet, wallet_new_intr_address)
{
    opened_wallet.ws[WALLET_KEYS_INTR].hdkey.depth = 4;
    bip32_key_from_parent_fake.custom_fake = [](
        const struct ext_key *hdkey,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        output->priv_key[0] = BIP32_FLAG_KEY_PRIVATE;
        output->depth = 5;
        return WALLY_OK;
    };

    // get_address
    //  - get_scriptpubkey_from_hdkey
    wally_scriptpubkey_p2tr_from_bytes_fake.custom_fake = [](
        const unsigned char *bytes,
        size_t bytes_len,
        uint32_t flags,
        unsigned char *bytes_out,
        size_t len,
        size_t *written
    ) -> int {
        *written = len;
        return WALLY_OK;
    };
    address_from_scriptpubkey_fake.return_val = 0;

    // save_index_file
    fopen_fake.return_val = (FILE *)1;

    char addr[ADDRESS_STR_MAX];
    int rc = wallet_new_intr_address(addr, NULL, NULL);
    ASSERT_EQ(rc, 0);
}

// wallet_new_intr_address
//  - new_address
//    - get_addr_hdkey
//    - get_address
//      - len == NULL
TEST_F(TestWallet, wallet_new_intr_address_fail_len_null)
{
    static uint8_t dummy_spk[WALLY_SCRIPTPUBKEY_P2TR_LEN];

    opened_wallet.ws[WALLET_KEYS_INTR].hdkey.depth = 4;
    bip32_key_from_parent_fake.custom_fake = [](
        const struct ext_key *hdkey,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        output->priv_key[0] = BIP32_FLAG_KEY_PRIVATE;
        output->depth = 5;
        return WALLY_OK;
    };

    // get_address
    //  - get_scriptpubkey_from_hdkey
    wally_scriptpubkey_p2tr_from_bytes_fake.custom_fake = [](
        const unsigned char *bytes,
        size_t bytes_len,
        uint32_t flags,
        unsigned char *bytes_out,
        size_t len,
        size_t *written
    ) -> int {
        fakes_data(dummy_spk, sizeof(dummy_spk));
        memcpy(bytes_out, dummy_spk, len);
        *written = len;
        return WALLY_OK;
    };
    address_from_scriptpubkey_fake.return_val = 0;

    // save_index_file
    // fopen_fake.return_val = (FILE *)1;

    char addr[ADDRESS_STR_MAX];
    uint8_t spk[WALLY_SCRIPTPUBKEY_P2TR_LEN - 1];
    int rc = wallet_new_intr_address(addr, spk, NULL);
    ASSERT_EQ(rc, 1);
}

// wallet_new_intr_address
//  - new_address
//    - get_addr_hdkey
//    - get_address
//      - *len < written
TEST_F(TestWallet, wallet_new_intr_address_fail_spk_len)
{
    static uint8_t dummy_spk[WALLY_SCRIPTPUBKEY_P2TR_LEN];

    opened_wallet.ws[WALLET_KEYS_INTR].hdkey.depth = 4;
    bip32_key_from_parent_fake.custom_fake = [](
        const struct ext_key *hdkey,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        output->priv_key[0] = BIP32_FLAG_KEY_PRIVATE;
        output->depth = 5;
        return WALLY_OK;
    };

    // get_address
    //  - get_scriptpubkey_from_hdkey
    wally_scriptpubkey_p2tr_from_bytes_fake.custom_fake = [](
        const unsigned char *bytes,
        size_t bytes_len,
        uint32_t flags,
        unsigned char *bytes_out,
        size_t len,
        size_t *written
    ) -> int {
        fakes_data(dummy_spk, sizeof(dummy_spk));
        memcpy(bytes_out, dummy_spk, len);
        *written = len;
        return WALLY_OK;
    };
    address_from_scriptpubkey_fake.return_val = 0;

    // save_index_file
    // fopen_fake.return_val = (FILE *)1;

    char addr[ADDRESS_STR_MAX];
    uint8_t spk[WALLY_SCRIPTPUBKEY_P2TR_LEN - 1];
    size_t len = sizeof(spk);
    int rc = wallet_new_intr_address(addr, spk, &len);
    ASSERT_EQ(rc, 1);
}

// wallet_new_intr_address(spk)
//  - new_address
//    - get_addr_hdkey
//    - get_address
//    - save_index_file
TEST_F(TestWallet, wallet_new_intr_address_spk)
{
    static uint8_t dummy_spk[WALLY_SCRIPTPUBKEY_P2TR_LEN];

    opened_wallet.ws[WALLET_KEYS_INTR].hdkey.depth = 4;
    bip32_key_from_parent_fake.custom_fake = [](
        const struct ext_key *hdkey,
        uint32_t child_num,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        output->priv_key[0] = BIP32_FLAG_KEY_PRIVATE;
        output->depth = 5;
        return WALLY_OK;
    };

    // get_address
    //  - get_scriptpubkey_from_hdkey
    wally_scriptpubkey_p2tr_from_bytes_fake.custom_fake = [](
        const unsigned char *bytes,
        size_t bytes_len,
        uint32_t flags,
        unsigned char *bytes_out,
        size_t len,
        size_t *written
    ) -> int {
        fakes_data(dummy_spk, sizeof(dummy_spk));
        memcpy(bytes_out, dummy_spk, len);
        *written = len;
        return WALLY_OK;
    };
    address_from_scriptpubkey_fake.return_val = 0;

    // save_index_file
    fopen_fake.return_val = (FILE *)1;

    char addr[ADDRESS_STR_MAX];
    uint8_t spk[WALLY_SCRIPTPUBKEY_P2TR_LEN];
    size_t len = sizeof(spk);
    int rc = wallet_new_intr_address(addr, spk, &len);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(len, (size_t)WALLY_SCRIPTPUBKEY_P2TR_LEN);
    ASSERT_EQ(memcmp(spk, dummy_spk, WALLY_SCRIPTPUBKEY_P2TR_LEN), 0);
}

////////////////////////////////////////////
// wallet_search_scriptpubkey

TEST_F(TestWallet, wallet_search_scriptpubkey)
{
    int detect = 0;
    struct ext_key hdkey;
    uint8_t spk[WALLY_SCRIPTPUBKEY_P2TR_LEN - 1] = {0};
    int rc = wallet_search_scriptpubkey(&detect, &hdkey, spk, sizeof(spk));
    ASSERT_EQ(rc, 1);
}


/////////////////////////////////////////////////
// Private functions
/////////////////////////////////////////////////

////////////////////////////////////////////
// load_wallet

////////////////////////////////////////////
// load_mnemonic_file

////////////////////////////////////////////
// load_index_file

////////////////////////////////////////////
// create_wallet

////////////////////////////////////////////
// create_mnemonic_file

////////////////////////////////////////////
// save_index_file

////////////////////////////////////////////
// create_masterkey

TEST_F(TestWallet, create_masterkey_ok_regtest)
{
    int rc;
    struct ext_key hdkey;
    const char MNEMONIC[] = "";
    static uint32_t network_version;

    bip39_mnemonic_to_seed_fake.custom_fake = [](
        const char *mnemonic,
        const char *passphrase,
        unsigned char *bytes_out,
        size_t len,
        size_t *written
    ) -> int {
        *written = BIP39_SEED_LEN_512;
        return WALLY_OK;
    };
    bip32_key_from_seed_fake.custom_fake = [](
        const unsigned char *bytes,
        size_t bytes_len,
        uint32_t version,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        network_version = version;
        return WALLY_OK;
    };

    rc = create_masterkey(&hdkey, MNEMONIC);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(network_version, (uint32_t)BIP32_VER_TEST_PRIVATE);
}

TEST_F(TestWallet, create_masterkey_ok_mainnet)
{
    int rc;
    struct ext_key hdkey;
    const char MNEMONIC[] = "";
    static uint32_t network_version;

    conf_get_fake.custom_fake = []() -> const struct conf* {
        static const struct conf DEFAULT_CONF = {
            .network = NETWORK_MAINNET,
            .wally_network = WALLY_NETWORK_BITCOIN_MAINNET,
            .addr_family = "bc"
        };
        return &DEFAULT_CONF;
    };
    bip39_mnemonic_to_seed_fake.custom_fake = [](
        const char *mnemonic,
        const char *passphrase,
        unsigned char *bytes_out,
        size_t len,
        size_t *written
    ) -> int {
        *written = BIP39_SEED_LEN_512;
        return WALLY_OK;
    };
    bip32_key_from_seed_fake.custom_fake = [](
        const unsigned char *bytes,
        size_t bytes_len,
        uint32_t version,
        uint32_t flags,
        struct ext_key *output
    ) -> int {
        network_version = version;
        return WALLY_OK;
    };

    rc = create_masterkey(&hdkey, MNEMONIC);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(network_version, (uint32_t)BIP32_VER_MAIN_PRIVATE);
}

////////////////////////////////////////////
// new_address

////////////////////////////////////////////
// get_addr_hdkey

////////////////////////////////////////////
// get_address

////////////////////////////////////////////
// get_scriptpubkey_from_hdkey

TEST_F(TestWallet, get_scriptpubkey_from_hdkey)
{
    struct ext_key hdkey = {
        .depth = 4, // != 5
    };

    int rc = get_scriptpubkey_from_hdkey(NULL, NULL, &hdkey);
    ASSERT_EQ(rc, 1);
}
