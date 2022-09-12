#pragma once

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

#include "../common/buffer.h"

/**
 * Handler for SIGN_MSG command. If successfully parse BIP32 path, 
 * sign hash and send APDU response.
 *
 * @see G_context.bip32_path,
 * G_context.tx_info.signature and G_context.tx_info.v.
 *
 * @param[in,out] cdata
 *   Command data with BIP32 path and hash (Pedersen).
 *
 * @return zero or positive integer if success, negative integer otherwise.
 *
 */
int handler_sign_hash(buffer_t *cdata, uint8_t chunk, bool display);