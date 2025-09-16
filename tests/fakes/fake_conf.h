#ifndef FAKE_CONF_H_
#define FAKE_CONF_H_

#include "fff.h"

#include "conf.h"

DECLARE_FAKE_VALUE_FUNC(int, conf_load, const char *);
DECLARE_FAKE_VALUE_FUNC(const struct conf *, conf_get);

#endif /* FAKE_CONF_H_ */
