#ifndef FAKES_H_
#define FAKES_H_

#include "fake_address.h"
#include "fake_conf.h"
#include "fake_misc.h"
#include "fake_tx.h"
#include "fake_wallet.h"

#include "fake_linux.h"
#include "fake_wally.h"

void fakes_init();
void fakes_data(void *data, size_t len);

#endif /* FAKES_H_ */
