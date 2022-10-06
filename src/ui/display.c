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

#pragma GCC diagnostic ignored "-Wformat-invalid-specifier"  // snprintf
#pragma GCC diagnostic ignored "-Wformat-extra-args"         // snprintf

#include <stdbool.h>  // bool
#include <string.h>   // memset

#include "os.h"
#include "ux.h"
#include "glyphs.h"

#include "display.h"
#include "constants.h"
#include "../globals.h"
#include "../io.h"
#include "../sw.h"
#include "../address.h"
#include "action/validate.h"
#include "../transaction/types.h"
#include "../common/bip32.h"
#include "../common/format.h"
#include "../transaction/types.h"

static action_validate_cb g_validate_callback;
static char g_bip32_path[60];
static char g_pubkey[134];
static char g_hash[68];

static char g_account_address[68];
static char g_to_address[68];
static char g_selector[32];

static char g_calldata_0[65];
static char g_calldata_name_0[32];
static char g_calldata_1[65];
static char g_calldata_name_1[32];
static char g_calldata_2[65];
static char g_calldata_name_2[32];


int format_calldata_display(char* output, uint8_t output_size, callData_item_t* data) {
    uint8_t bytes = 32;
    uint8_t idx = 0;
    uint32_t val = 0;

    memset(output, 0, output_size);
    
    while ((data->item[idx++] == 0) && (bytes > 0))
        bytes--;

    if (bytes > 4){
        snprintf(output, output_size, "%.*H", bytes, data->item);
    }
    else {
        val = 
            ((uint32_t)data->item[28] << 24) +
            ((uint32_t)data->item[29] << 16) +
            ((uint32_t)data->item[30] << 8) +
            (uint32_t)data->item[31];    
 
        snprintf(output, output_size, "%d", val);
    }
    return 0;
}

int format_calldata_name_display(char* output, uint8_t output_size, callData_item_t* data) {
    memset(output, 0, output_size);
    if (data->name_len > 0) {
        snprintf(output, output_size, "%.*s", data->name_len, data->name);
    }
    else {
        snprintf(output, output_size, "%s", "Calldata:\0");
    }
    return 0;
}


// Step with icon and text
UX_STEP_NOCB(ux_display_confirm_pubkey_step, pn, {&C_icon_eye, "Confirm Pubkey"});
// Step with title/text for BIP32 path
UX_STEP_NOCB(ux_display_path_step,
             bnnn_paging,
             {
                 .title = "Path",
                 .text = g_bip32_path,
             });
// Step with title/text for address
UX_STEP_NOCB(ux_display_pubkey_step,
             bnnn_paging,
             {
                 .title = "Pubkey",
                 .text = g_pubkey,
             });
// Step with approve button
UX_STEP_CB(ux_display_approve_step,
           pb,
           (*g_validate_callback)(true),
           {
               &C_icon_validate_14,
               "Approve",
           });
// Step with reject button
UX_STEP_CB(ux_display_reject_step,
           pb,
           (*g_validate_callback)(false),
           {
               &C_icon_crossmark,
               "Reject",
           });

// FLOW to display address and BIP32 path:
// #1 screen: eye icon + "Confirm Pubkey"
// #2 screen: display BIP32 Path
// #3 screen: display pubkey
// #4 screen: approve button
// #5 screen: reject button
UX_FLOW(ux_display_pubkey_flow,
        &ux_display_confirm_pubkey_step,
        &ux_display_path_step,
        &ux_display_pubkey_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

int ui_display_pubkey() {
    if (G_context.req_type != CONFIRM_ADDRESS || G_context.state != STATE_NONE) {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    memset(g_bip32_path, 0, sizeof(g_bip32_path));
    if (!bip32_path_format(G_context.bip32_path,
                           G_context.bip32_path_len,
                           g_bip32_path,
                           sizeof(g_bip32_path))) {
        return io_send_sw(SW_DISPLAY_BIP32_PATH_FAIL);
    }

    memset(g_pubkey, 0, sizeof(g_pubkey));
    /*uint8_t address[ADDRESS_LEN] = {0};
    if (!address_from_pubkey(G_context.pk_info.raw_public_key, address, sizeof(address))) {
        return io_send_sw(SW_DISPLAY_ADDRESS_FAIL);
    }*/
    snprintf(g_pubkey, sizeof(g_pubkey), "0x04%.*H", 64, G_context.pk_info.raw_public_key);

    g_validate_callback = &ui_action_validate_pubkey;

    ux_flow_init(0, ux_display_pubkey_flow, NULL);

    return 0;
}

// Step with icon and text
UX_STEP_NOCB(ux_display_review_step,
             pnn,
             {
                 &C_icon_eye,
                 "Review",
                 "Tx",
             });
// Step with title/text for amount
UX_STEP_NOCB(ux_display_account_address_step,
             bnnn_paging,
             {
                 .title = "Account Address",
                 .text = g_account_address,
             });

UX_STEP_NOCB(ux_display_to_address_step,
             bnnn_paging,
             {
                 .title = "Target Address",
                 .text = g_to_address,
             });

UX_STEP_NOCB(ux_display_selector_step,
             bnnn_paging,
             {
                 .title = "Selector",
                 .text = g_selector,
             });

UX_STEP_NOCB(ux_display_calldata_0_step,
             bnnn_paging,
             {
                 .title = g_calldata_name_0,
                 .text = g_calldata_0,
             });

UX_STEP_NOCB(ux_display_calldata_1_step,
             bnnn_paging,
             {
                 .title = g_calldata_name_1,
                 .text = g_calldata_1,
             });

UX_STEP_NOCB(ux_display_calldata_2_step,
             bnnn_paging,
             {
                 .title = "Calldata #3",
                 .text = g_calldata_2,
             });

// FLOW to display transaction information:
// #1 screen : eye icon + "Review Transaction"
// #2 screen : display account contract address
// #3 screen : display target contract address
// #4 screen : display selector
// #5 screen : approve button
// #6 screen : reject button

const ux_flow_step_t *ux_display_transaction_flow[16 + 1];

int ui_display_transaction() {
    
    uint8_t index = 0;
    
    if (G_context.req_type != CONFIRM_TRANSACTION || G_context.state != STATE_PARSED) {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    ux_display_transaction_flow[index++] = &ux_display_review_step;

    memset(g_account_address, 0, sizeof(g_account_address));
    snprintf(g_account_address, sizeof(g_account_address), "0x%.*H", 32, G_context.tx_info.transaction.sender_address);
    ux_display_transaction_flow[index++] = &ux_display_account_address_step;

    memset(g_to_address, 0, sizeof(g_to_address));
    snprintf(g_to_address, sizeof(g_to_address), "0x%.*H", 32, G_context.tx_info.transaction.calldata.to);
    ux_display_transaction_flow[index++] = &ux_display_to_address_step;

    memset(g_selector, 0, sizeof(g_selector));
    snprintf(g_selector, G_context.tx_info.transaction.calldata.entry_point_length + 1, "%s", G_context.tx_info.transaction.calldata.entry_point);
    ux_display_transaction_flow[index++] = &ux_display_selector_step;

    /* start display calldata */

    if (G_context.tx_info.transaction.calldata.calldata_length >= 1) {
        format_calldata_name_display(g_calldata_name_0, sizeof(g_calldata_name_0), &G_context.tx_info.transaction.calldata.calldata[0]);
        format_calldata_display(g_calldata_0, sizeof(g_calldata_0), &G_context.tx_info.transaction.calldata.calldata[0]);
        ux_display_transaction_flow[index++] = &ux_display_calldata_0_step;
    }

    if (G_context.tx_info.transaction.calldata.calldata_length >= 2) {
        format_calldata_name_display(g_calldata_name_1, sizeof(g_calldata_name_1), &G_context.tx_info.transaction.calldata.calldata[1]);
        format_calldata_display(g_calldata_1, sizeof(g_calldata_1), &G_context.tx_info.transaction.calldata.calldata[1]);
        ux_display_transaction_flow[index++] = &ux_display_calldata_1_step;
    }

    if (G_context.tx_info.transaction.calldata.calldata_length >= 3) {
        format_calldata_name_display(g_calldata_name_2, sizeof(g_calldata_name_2), &G_context.tx_info.transaction.calldata.calldata[2]);
        format_calldata_display(g_calldata_2, sizeof(g_calldata_2), &G_context.tx_info.transaction.calldata.calldata[2]);
        ux_display_transaction_flow[index++] = &ux_display_calldata_2_step;
    }

    /* end display calldata */

    g_validate_callback = &ui_action_validate;
    ux_display_transaction_flow[index++] = &ux_display_approve_step;

    ux_display_transaction_flow[index++] = &ux_display_reject_step;
    
    ux_display_transaction_flow[index++] = FLOW_END_STEP;

    ux_flow_init(0, ux_display_transaction_flow, NULL);

    return 0;
}

UX_STEP_NOCB(ux_display_review_hash_step,
             pnn,
             {
                 &C_icon_eye,
                 "Review",
                 "Hash",
             });

UX_STEP_NOCB(ux_display_hash_step,
             bnnn_paging,
             {
                 .title = "Hash",
                 .text = g_hash,
             });

// FLOW to display hash information:
// #1 screen : eye icon + "Review Hash"
// #2 screen : display hash
// #3 screen : approve button
// #4 screen : reject button
UX_FLOW(ux_display_hash_flow,
        &ux_display_review_hash_step,
        &ux_display_hash_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

int ui_display_hash() {
    if (G_context.req_type != CONFIRM_HASH || G_context.state != STATE_PARSED) {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    memset(g_hash, 0, sizeof(g_hash));
    snprintf(g_hash, sizeof(g_hash), "0x%.*H", 32, G_context.hash_info.m_hash);

    g_validate_callback = &ui_action_validate;

    ux_flow_init(0, ux_display_hash_flow, NULL);

    return 0;
}


