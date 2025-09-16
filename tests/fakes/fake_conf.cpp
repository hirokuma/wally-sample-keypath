#include "fff.h"
#include "fakes.h"

DEFINE_FAKE_VALUE_FUNC(int, conf_load, const char *);
DEFINE_FAKE_VALUE_FUNC(const struct conf *, conf_get);
