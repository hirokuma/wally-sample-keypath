#include "fff.h"
#include "fakes.h"

DEFINE_FAKE_VALUE_FUNC(int, address_from_scriptpubkey, char*, const uint8_t *, size_t);
DEFINE_FAKE_VALUE_FUNC(int, address_to_scriptpubkey, uint8_t*, size_t *, const char *);
