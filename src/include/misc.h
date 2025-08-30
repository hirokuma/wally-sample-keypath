#ifndef MISC_H_
#define MISC_H_

#include <stddef.h>
#include <stdint.h>

void dump(const uint8_t *data, size_t len);
int fill_random(uint8_t *data, size_t len);

#endif /* MISC_H_ */
