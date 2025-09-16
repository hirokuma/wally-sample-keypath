#include "fff.h"
#include "fakes.h"

DEFINE_FAKE_VALUE_FUNC(int, stat, const char *, struct stat *);
DEFINE_FAKE_VALUE_FUNC(FILE*, fopen, const char *, const char *);
DEFINE_FAKE_VALUE_FUNC(char *, fgets, char *, int, FILE*);
DEFINE_FAKE_VALUE_FUNC(int, fclose, FILE*);
DEFINE_FAKE_VALUE_FUNC_VARARG(int, fscanf, FILE*, const char *, ...);
DEFINE_FAKE_VALUE_FUNC_VARARG(int, fprintf, FILE*, const char *, ...);
