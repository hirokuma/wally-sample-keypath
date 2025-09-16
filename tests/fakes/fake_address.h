#ifndef FAKE_ADDRESS_H_
#define FAKE_ADDRESS_H_

#include <stddef.h>
#include <stdint.h>

#include "fff.h"

#include "address.h"

DECLARE_FAKE_VALUE_FUNC(int, address_from_scriptpubkey, char*, const uint8_t *, size_t);
DECLARE_FAKE_VALUE_FUNC(int, address_to_scriptpubkey, uint8_t*, size_t *, const char *);

#endif /* FAKE_ADDRESS_H_ */
