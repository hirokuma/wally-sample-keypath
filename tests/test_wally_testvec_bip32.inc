struct Bip32TestVector {
    const char* base58Priv;
    const char* chaincode;
    const char* priv;
    const char* pub;
    const char* path;
    uint32_t    childnum;
};

// https://github.com/bitcoinjs/bip32/blob/1326d4ed940467285c74ca698c6f2a9d2f042871/test/fixtures/index.json#L3-L90
static const struct Bip32TestVector bip32_test_vectors[] = {
    {
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
        "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
        "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
        "m",
        0,
    },
    {
        "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
        "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
        "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
        "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
        "m/0'",
        BIP32_INITIAL_HARDENED_CHILD | 0,
    },
    {
        "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
        "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
        "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
        "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c",
        "m/0'/1",
        1,
    },
    {
        "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
        "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f",
        "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
        "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2",
        "m/0'/1/2'",
        BIP32_INITIAL_HARDENED_CHILD | 2,
    },
    {
        "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
        "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd",
        "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
        "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29",
        "m/0'/1/2'/2",
        2,
    },
    {
        "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
        "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e",
        "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
        "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011",
        "m/0'/1/2'/2/1000000000",
        1000000000,
    },
};
