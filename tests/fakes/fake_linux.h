#ifndef FAKE_LINUX_H_
#define FAKE_LINUX_H_

#include "fff.h"

#include <stdio.h>
#include <sys/stat.h>
#include <string.h>

DECLARE_FAKE_VALUE_FUNC(int, stat, const char *, struct stat *);
DECLARE_FAKE_VALUE_FUNC(FILE *, fopen, const char *, const char *);
DECLARE_FAKE_VALUE_FUNC(char *, fgets, char *, int, FILE*);
DECLARE_FAKE_VALUE_FUNC(int, fclose, FILE*);
DECLARE_FAKE_VALUE_FUNC_VARARG(int, fscanf, FILE*, const char *, ...);
DECLARE_FAKE_VALUE_FUNC_VARARG(int, fprintf, FILE*, const char *, ...);

#endif /* FAKE_LINUX_H_ */
