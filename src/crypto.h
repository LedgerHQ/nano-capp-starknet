
#pragma once

#include <stdint.h>  // uint*_t

#include "os.h"
#include "cx.h"

#include "types.h"


/**
 * Initialize public key given private key.
 *
 * @param[in]  bip32_path
 *   Pointer to derivation path.
 * @param[out] bip32_path_len
 *   Derivation path length
 * @param[out] raw_public_key
 *   Pointer to raw public key.
 *
 * @return 0 if success, -1 otherwise.
 *
 * @throw INVALID_PARAMETER
 *
 */
int crypto_init_public_key(uint32_t *bip32_path,
                           uint8_t bip32_path_len,
                           uint8_t raw_public_key[static 64]);

/**
 * Sign message hash from global context.
 *
 * @see G_context.bip32_path, G_context.hash_info
 *
 * @return 0 if success, -1 otherwise.
 *
 * @throw INVALID_PARAMETER
 *
 */
int crypto_sign_hash(uint32_t *bip32_path, uint8_t bip32_path_len, hash_ctx_t *hash_info);

/**
 * Derive private key given EIP-2645 path.
 *
 * @param[out] private_key
 *   Pointer to private key.
 * @param[in]  bip32_path
 *   Pointer to buffer with BIP32 path.
 * @param[in]  bip32_path_len
 *   Number of path in BIP32 path.
 *
 * @return 0 if success, -1 otherwise.
 *
 * @throw INVALID_PARAMETER
 *
 */
int eip2645_derive_private_key(cx_ecfp_private_key_t *private_key,
                              const uint32_t *bip32_path,
                              uint8_t bip32_path_len);
