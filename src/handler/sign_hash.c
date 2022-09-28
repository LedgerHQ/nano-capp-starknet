/*****************************************************************************
 *   Ledger App Starknet
 *   (c) 2022 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // memset, explicit_bzero

#include "os.h"
#include "cx.h"

#include "sign_hash.h"
#include "../globals.h"
#include "../types.h"
#include "../io.h"
#include "../sw.h"
#include "../crypto.h"
#include "../common/buffer.h"
#include "../ui/display.h"
#include "../helper/send_response.h"

int handler_sign_hash(buffer_t *cdata, uint8_t chunk, bool display) {
    if (chunk == 0) {  // first APDU, parse BIP32 path
        explicit_bzero(&G_context, sizeof(G_context));
        G_context.req_type = CONFIRM_HASH;
        G_context.state = STATE_NONE;

        if (!buffer_read_u8(cdata, &G_context.bip32_path_len) ||
            !buffer_read_bip32_path(cdata,
                                    G_context.bip32_path,
                                    (size_t) G_context.bip32_path_len)) {
            return io_send_sw(SW_WRONG_DATA_LENGTH);
        }

        return io_send_sw(SW_OK);
    } else {  // second APDU, retrieve and sign hash
        if (G_context.req_type != CONFIRM_HASH) {
            return io_send_sw(SW_BAD_STATE);
        }

        // last APDU, let's parse and sign
        if (!buffer_move(cdata, G_context.hash_info.m_hash, cdata->size)) {
            return io_send_sw(SW_WRONG_DATA_LENGTH);
        }

        G_context.state = STATE_PARSED;

        PRINTF("Hash: %.*H\n", sizeof(G_context.hash_info.m_hash), G_context.hash_info.m_hash);

        if (display) 
            return ui_display_hash();
        else {
            G_context.state = STATE_APPROVED;

            if (crypto_sign_hash(G_context.bip32_path, G_context.bip32_path_len, &G_context.hash_info) < 0) {
                G_context.state = STATE_NONE;
                return io_send_sw(SW_SIGNATURE_FAIL);
            } else {
                return helper_send_response_sig(&G_context.hash_info);
            }
        }
    }
}