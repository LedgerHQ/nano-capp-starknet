#pragma once

#include <stdint.h>  // uint*_t

#include "transaction/types.h"

int hash_tx(transaction_t *tx, uint8_t* hash);

void call_pedersen(
    uint8_t *res,
    uint8_t *ab,
	uint8_t n);
 
