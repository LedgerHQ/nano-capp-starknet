#pragma once

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

#include "../common/buffer.h"

int handler_compute_pedersen(buffer_t *cdata, uint8_t n);
