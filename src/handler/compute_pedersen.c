/*****************************************************************************
 *   Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS.
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

#include "compute_pedersen.h"
#include "../sw.h"
#include "../globals.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../ui/action/validate.h"
#include "../common/buffer.h"
#include "../transaction/types.h"
#include "../transaction/deserialize.h"
#include "../hash.h"
#include "../helper/send_response.h"

int handler_compute_pedersen(buffer_t *cdata, uint8_t n) { 
	
	explicit_bzero(&G_context, sizeof(G_context));
	G_context.req_type = COMPUTE_PEDERSEN;
    G_context.state = STATE_NONE;
	
	if (!buffer_move(cdata, G_context.pn_info.ab, 64)) {

		return io_send_sw(SW_WRONG_DATA_LENGTH);

    } else {  // Compute Pedersen hash
		
		G_context.state = STATE_PARSED;
		
		call_pedersen(G_context.hash_info.m_hash, G_context.pn_info.ab, n);
		
		PRINTF("Hash Pedersen: %.*h\n", 32, G_context.hash_info.m_hash);
		
		G_context.state = STATE_APPROVED;
		return helper_send_response_hash(&G_context.hash_info);
    }

    return 0;
}
