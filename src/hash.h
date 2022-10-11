#pragma once

#include <stdint.h>  // uint*_t

#include "transaction/types.h"

int hash_tx(transaction_t *tx, uint8_t* hash);