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

#include "deserialize.h"
#include "utils.h"
#include "types.h"
#include "../common/buffer.h"
#include "os.h"


/* chunk 1 = accountAddress (32 bytes) + maxFee (32 bytes) + nonce (32 bytes) + version (32 bytes) = 128 bytes*/
/* chunk 2 = to (32 bytes) + selector length (1 byte) + selector (selector length bytes) + call_data length (1 byte) */
/* chunk . = calldata */

parser_status_e transaction_deserialize(buffer_t *buf, transaction_t *tx) {

    int i;

    if (buf->size > MAX_TX_LEN) {
        return WRONG_LENGTH_ERROR;
    }

    tx->sender_address = (uint8_t *) (buf->ptr + buf->offset);
    if (!buffer_seek_cur(buf, 32)) {
        return SENDER_ADDRESS_PARSING_ERROR;
    }
    
    PRINTF("senderAddress OK %d \n", buf->offset);

    tx->max_fee = (uint8_t *) (buf->ptr + buf->offset);
    if (!buffer_seek_cur(buf, 32)) {
        return MAX_FEE_PARSING_ERROR;
    }
    
    
    PRINTF("maxFee OK %d \n", buf->offset);

    tx->nonce = (uint8_t *) (buf->ptr + buf->offset);
    if (!buffer_seek_cur(buf, 32)) {
        return NONCE_PARSING_ERROR;
    }

    
    PRINTF("nonce OK %d \n", buf->offset);

    tx->version = (uint8_t *) (buf->ptr + buf->offset);
    if (!buffer_seek_cur(buf, 32)) {
        return VERSION_PARSING_ERROR;
    }

    PRINTF("version OK %d \n", buf->offset);

    tx->chain_id = (uint8_t *) (buf->ptr + buf->offset);
    if (!buffer_seek_cur(buf, 32)) {
        return VERSION_PARSING_ERROR;
    }
    PRINTF("chain_id OK %d \n", buf->offset);

    tx->calldata.callarray_length = 1;

    tx->calldata.to = (uint8_t *) (buf->ptr + buf->offset);
    if (!buffer_seek_cur(buf, 32)) {
        return TO_PARSING_ERROR;
    }
    
    PRINTF("to OK %d \n", buf->offset);

    if (!buffer_read_u8(buf, &(tx->calldata.entry_point_length))) {
        return SELECTOR_LENGTH_PARSING_ERROR;
    }

    PRINTF("entry_point_length OK %d \n", buf->offset);

    tx->calldata.entry_point = (uint8_t *) (buf->ptr + buf->offset);
    if (!buffer_seek_cur(buf, tx->calldata.entry_point_length)) {
        return SELECTOR_PARSING_ERROR;
    }

    PRINTF("selector OK %d \n", buf->offset);

    tx->calldata.data_offset = 0;

    if (!buffer_read_u8(buf, &(tx->calldata.data_length))) {
        return DATA_LENGTH_PARSING_ERROR;
    }

    PRINTF("data_length OK %d \n", buf->offset);

    tx->calldata.calldata_length = tx->calldata.data_length;
    
    for (i = 0; i < tx->calldata.calldata_length; i++){
        buffer_read_u8(buf, &(tx->calldata.calldata[i].name_len));
        tx->calldata.calldata[i].name = (char *) (buf->ptr + buf->offset);
        buffer_seek_cur(buf, tx->calldata.calldata[i].name_len);
        tx->calldata.calldata[i].item = (uint8_t *) (buf->ptr + buf->offset);
        buffer_seek_cur(buf, 32);
    }

    PRINTF("calldata OK %d \n", buf->offset);

    return (buf->offset == buf->size) ? PARSING_OK : WRONG_LENGTH_ERROR;
}
