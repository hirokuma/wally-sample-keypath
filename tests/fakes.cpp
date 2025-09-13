#include "fakes.h"

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
}
