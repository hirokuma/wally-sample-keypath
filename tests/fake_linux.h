#ifndef FAKE_LINUX_H_
#define FAKE_LINUX_H_

#include "fff/fff.h"

#include <sys/stat.h>

DECLARE_FAKE_VALUE_FUNC(int, stat, const char *, struct stat *);

#endif /* FAKE_LINUX_H_ */
