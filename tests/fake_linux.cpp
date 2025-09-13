#include "fff/fff.h"
#include "fakes.h"

#ifdef UNIT_TEST

DEFINE_FAKE_VALUE_FUNC(int, stat, const char *, struct stat *);

#endif // UNIT_TEST
